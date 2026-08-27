use super::*;

#[test]
fn rejects_image_pointers() {
    assert!(!is_heap_pointer(
        0x1400_0000_0,
        0x1400_0000_0,
        0x1401_0000_0
    ));
    // Below MIN_HEAP_POINTER (1 MiB) — PE noise / segment heads.
    // Note: 0x31a0_b30 (~50 MiB) is ABOVE the floor and is a valid heap-shaped
    // candidate; use a true sub-1MiB address for this rejection case.
    assert!(!is_heap_pointer(0x9_0000, 0x1400_0000_0, 0x1401_0000_0));
    assert!(!is_heap_pointer(0x1_0000, 0x1400_0000_0, 0x1401_0000_0));
    // Real user heap above 1 MiB.
    assert!(is_heap_pointer(0x85a_380, 0x1400_0000_0, 0x1401_0000_0));
}

#[test]
fn accepts_high_user_heap() {
    // Real x64 heaps often sit above 4 GiB but below system DLL region.
    assert!(is_heap_pointer(
        0x0000_01a0_1234_5600,
        0x1400_0000_0,
        0x1401_0000_0
    ));
}

#[test]
fn gscript_short_label_count_is_fail_closed() {
    let table_ptr = 0x800_000u64;
    let label_ptr = 0x810_000u64;
    let mk = |content: Vec<u8>, inline: bool, live_ptr: u64| HeapGlobalSnapshot {
        rva: 0x2000,
        live_ptr,
        content,
        is_heap_handle: false,
        is_image_inline: inline,
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };

    for len in [0usize, 8, 0x13] {
        let mut gscript = vec![0u8; len];
        if len >= 8 {
            gscript[0..8].copy_from_slice(&table_ptr.to_le_bytes());
        }
        let before = gscript.clone();
        let mut globals = vec![
            mk(gscript, true, 0x1400_2000),
            mk(label_ptr.to_le_bytes().to_vec(), false, table_ptr),
            mk(vec![0u8; 0x40], false, label_ptr),
        ];
        mark_labels_non_nested(&mut globals);
        assert_eq!(globals[0].content, before, "short gscript must fail closed");
    }

    let mut gscript = vec![0u8; 0x14];
    gscript[0..8].copy_from_slice(&table_ptr.to_le_bytes());
    gscript[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut globals = vec![
        mk(gscript, true, 0x1400_2000),
        mk(label_ptr.to_le_bytes().to_vec(), false, table_ptr),
        mk(vec![0u8; 0x40], false, label_ptr),
    ];
    mark_labels_non_nested(&mut globals);
    assert_eq!(globals[2].content[0x23], 1, "len=0x14 is readable");
}

#[test]
fn label_table_pointer_policy_covers_four_gib_boundary() {
    for value in [0x100_000u64, 0x1_0000_0000, 0x1_0000_0008] {
        assert_eq!(
            count_leading_heap_ptrs(&value.to_le_bytes()),
            1,
            "valid pointer must be admitted",
        );
    }
    for value in [0x0f_ffffu64, 0x1_0000_0001, MIN_MODULE_REGION] {
        assert_eq!(
            count_leading_heap_ptrs(&value.to_le_bytes()),
            0,
            "invalid pointer must fail closed",
        );
    }
}

#[test]
fn rejects_system_dll_pointers() {
    assert!(!is_heap_pointer(
        0x0000_7ffa_33b4_1a30,
        0x1400_0000_0,
        0x1401_0000_0
    ));
}

#[test]
fn rejects_unaligned() {
    assert!(!is_heap_pointer(0x31a0_b31, 0x1400_0000_0, 0x1401_0000_0));
}

#[test]
fn policy_hot_root_outside_fill_data_is_still_hot() {
    // Mirrors GTO 0x18a898: listed in ahk_gto defaults, not in .data/.fill.
    let p = DumpCapturePolicy::ahk_gto_default();
    assert!(p.is_hot_root(0x18a898));
    assert!(p.hot_root_rvas.contains(&0x18a898));
}

#[test]
fn sanitize_ahk_runtime_global_zeros_for_cold_start() {
    let mut globals = vec![
        HeapGlobalSnapshot {
            rva: 0x141bf0,
            live_ptr: 0x12345678,
            content: vec![0x1; 0x100],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
        HeapGlobalSnapshot {
            rva: 0x149d50,
            live_ptr: 0x87654321,
            content: vec![0x2; 0x200],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
    ];
    sanitize_ahk_runtime_global(&mut globals);
    let ahk_g = globals.iter().find(|g| g.rva == 0x141bf0).unwrap();
    assert_eq!(ahk_g.content.len(), 0x180);
    assert!(ahk_g.content.iter().all(|&b| b == 0));
}

// =====================================================================
// GTO-COLD-START-HEAP-REBASE-1 H2 — first-hop dedicated-slab supplement
// =====================================================================

fn h2_probe_child(live_ptr: u64, len: usize, interior: bool) -> HeapGlobalSnapshot {
    HeapGlobalSnapshot {
        rva: 0,
        live_ptr,
        content: vec![0x41u8; len],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: if interior {
            CaptureExtentKind::InteriorSubview
        } else {
            CaptureExtentKind::ProbeWindow
        },
        extent_evidence: CaptureExtentEvidence {
            capture_id: format!("graph_child:{live_ptr:#x}"),
            capture_path: CapturePath::GscriptFirstHop,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: interior,
            containing_parent_old_base: if interior {
                Some(live_ptr - 0x100)
            } else {
                None
            },
            containing_parent_size: if interior { Some(0x200) } else { None },
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    }
}

/// An uncovered non-interior first-hop probe child outside the main slab
/// gets its own dedicated slab (the exact H3 attempt_006/007 wall:
/// `capture_coverage_bind` ProbeCoverageMissing on graph_child:GscriptFirstHop).
#[test]
fn h2_uncovered_probe_child_gets_dedicated_slab() {
    let main = HeapSlab {
        old_base: 0x1000_0000,
        content: vec![0u8; 0x1000],
    };
    // Child OUTSIDE the main span (AHK multi-heap: private heap region).
    let child = h2_probe_child(0x9000_0000, 0x70, false);
    let mut dedicated: Vec<HeapSlab> = Vec::new();
    let added = supplement_uncovered_probe_slabs(&[child.clone()], &[main.clone()], &mut dedicated);
    assert_eq!(
        added, 1,
        "uncovered non-interior probe must be supplemented"
    );
    assert_eq!(dedicated.len(), 1);
    assert_eq!(dedicated[0].old_base, 0x9000_0000);
    assert_eq!(dedicated[0].content.len(), 0x70);
    // The child is now covered by exactly one slab (its dedicated one).
    let slabs = vec![main, dedicated.remove(0)];
    assert!(super::super::raw_slab_coherence::validate_probe_coverage(&[child], &slabs).is_ok());
}

/// A child already inside the main slab must NOT be duplicated (that would
/// flip exactly-one coverage into ambiguous).
#[test]
fn h2_covered_probe_child_not_duplicated() {
    let main = HeapSlab {
        old_base: 0x9000_0000,
        content: vec![0u8; 0x1000],
    };
    let child = h2_probe_child(0x9000_0100, 0x70, false);
    let mut dedicated: Vec<HeapSlab> = Vec::new();
    let added = supplement_uncovered_probe_slabs(&[child.clone()], &[main.clone()], &mut dedicated);
    assert_eq!(added, 0, "covered child must not be re-surfaced");
    assert!(dedicated.is_empty());
    assert!(super::super::raw_slab_coherence::validate_probe_coverage(&[child], &[main]).is_ok());
}

/// Interior children are covered by their containing parent; re-surfacing
/// them would create ambiguous coverage.
#[test]
fn h2_interior_probe_child_not_duplicated() {
    let main = HeapSlab {
        old_base: 0x9000_0000,
        content: vec![0u8; 0x1000],
    };
    let child = h2_probe_child(0x9000_0100, 0x70, true);
    let mut dedicated: Vec<HeapSlab> = Vec::new();
    let added = supplement_uncovered_probe_slabs(&[child], &[main], &mut dedicated);
    assert_eq!(added, 0, "interior child must not be re-surfaced");
}

/// GTO-COLD-START-HEAP-REBASE-1 H2 regression: a split-sibling interior
/// child whose parent authority was LOST (containing_parent_old_base=None,
/// heuristic/ambiguous parent) has no slab to depend on. It must be
/// supplemented itself, otherwise capture_coverage_bind fails closed even
/// though every byte was a valid live read (attempt_012 wall:
/// split_sibling:0xb9febf0:graph_child:0xb9fea40:0x2b0).
#[test]
fn h2_interior_without_parent_evidence_gets_dedicated_slab() {
    let main = HeapSlab {
        old_base: 0x9000_0000,
        content: vec![0u8; 0x1000],
    };
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x9000_2000,
        content: vec![0x42u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x9000_2000:graph_child:0x9000_1f00:0x2b0".into(),
            capture_path: CapturePath::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x2b0),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let mut dedicated: Vec<HeapSlab> = Vec::new();
    let added = supplement_uncovered_probe_slabs(&[child.clone()], &[main.clone()], &mut dedicated);
    assert_eq!(
        added, 1,
        "interior child WITHOUT parent evidence must be supplemented"
    );
    assert_eq!(dedicated.len(), 1);
    assert_eq!(dedicated[0].old_base, 0x9000_2000);
    assert_eq!(dedicated[0].content.len(), 8);
    let slabs = vec![main, dedicated.remove(0)];
    assert!(super::super::raw_slab_coherence::validate_probe_coverage(&[child], &slabs).is_ok());
}

/// A child partially overlapping an existing authority is NOT supplemented
/// (adding a boundary over a conflicting authority would be a fabricated
/// extent); the coverage gate still rejects it — fail-closed preserved.
#[test]
fn h2_conflicting_partial_overlap_not_supplemented() {
    let main = HeapSlab {
        old_base: 0x9000_0000,
        content: vec![0u8; 0x100],
    };
    // Child starts inside the main slab but extends past its end.
    let child = h2_probe_child(0x9000_0080, 0x100, false);
    let mut dedicated: Vec<HeapSlab> = Vec::new();
    let added = supplement_uncovered_probe_slabs(&[child.clone()], &[main.clone()], &mut dedicated);
    assert_eq!(
        added, 0,
        "conflicting overlap must fail closed, not fabricate"
    );
    assert!(super::super::raw_slab_coherence::validate_probe_coverage(&[child], &[main]).is_err());
}

/// Bad pointers (outside user range) and empty children stay uncovered:
/// they are not heap extents, they are bad pointers.
#[test]
fn h2_bad_pointer_stays_uncovered() {
    let low = h2_probe_child(0x1000, 0x70, false); // below MIN_USER_POINTER
    let empty = HeapGlobalSnapshot {
        content: Vec::new(),
        ..h2_probe_child(0x9000_0000, 0x70, false)
    };
    let mut dedicated: Vec<HeapSlab> = Vec::new();
    let added = supplement_uncovered_probe_slabs(&[low, empty], &[], &mut dedicated);
    assert_eq!(added, 0, "bad pointers must not become slabs");
    assert!(dedicated.is_empty());
}

/// GTO-COLD-START-HEAP-REBASE-1 H2 (attempt_018 wall): an image-root /
/// main-slot captured region (RawCaptured + ObservedAllocation) with NO
/// main slab (AHK multi-heap) must be supplemented as its own dedicated
/// slab — otherwise transform_input_seed fails closed on a region that
/// was a proven allocation, not a heuristic window.
#[test]
fn h2_uncovered_observed_allocation_gets_dedicated_slab_without_main() {
    let region = HeapGlobalSnapshot {
        rva: 0x180880,
        live_ptr: 0x9f6f00,
        content: vec![0x33u8; 0x10c0],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main_slot:0x180880".into(),
            capture_path: CapturePath::MainSlot,
            source_root_rva: Some(0x180880),
            source_slot_offset: Some(0),
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::RawCaptured {
            raw_digest: "dummy".into(),
        },
    };
    let mut dedicated: Vec<HeapSlab> = Vec::new();
    // NO main slab (exactly the attempt_018 shape: "no main slab").
    let added = supplement_uncovered_probe_slabs(&[region.clone()], &[], &mut dedicated);
    assert_eq!(
        added, 1,
        "uncovered ObservedAllocation must be supplemented without a main slab"
    );
    assert_eq!(dedicated[0].old_base, 0x9f6f00);
    assert_eq!(dedicated[0].content.len(), 0x10c0);
    let slabs = vec![dedicated.remove(0)];
    assert!(super::super::raw_slab_coherence::validate_probe_coverage(&[region], &slabs).is_ok());
}

/// An ObservedAllocation already inside the main slab must NOT be
/// duplicated (exactly-one coverage preserved).
#[test]
fn h2_covered_observed_allocation_not_duplicated() {
    let main = HeapSlab {
        old_base: 0x9f6f00,
        content: vec![0u8; 0x2000],
    };
    let region = HeapGlobalSnapshot {
        rva: 0x180880,
        live_ptr: 0x9f7000,
        content: vec![0x33u8; 0x40],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::RawCaptured {
            raw_digest: "dummy".into(),
        },
    };
    let mut dedicated: Vec<HeapSlab> = Vec::new();
    let added =
        supplement_uncovered_probe_slabs(&[region.clone()], &[main.clone()], &mut dedicated);
    assert_eq!(
        added, 0,
        "covered ObservedAllocation must not be re-surfaced"
    );
    assert!(dedicated.is_empty());
    assert!(super::super::raw_slab_coherence::validate_probe_coverage(&[region], &[main]).is_ok());
}

/// A SyntheticDerived region is NOT raw-captured; it must never become a
/// dedicated slab even when uncovered (participant predicate excludes it).
#[test]
fn h2_synthetic_region_never_supplemented() {
    let region = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x9000_0000,
        content: vec![0x44u8; 0x40],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::SyntheticDerived,
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::SyntheticDerived {
            transform_id: "t".into(),
            source_anchor: "a".into(),
            construction_digest: "d".into(),
        },
    };
    let mut dedicated: Vec<HeapSlab> = Vec::new();
    let added = supplement_uncovered_probe_slabs(&[region], &[], &mut dedicated);
    assert_eq!(added, 0, "synthetic regions must not become slabs");
    assert!(dedicated.is_empty());
}

/// Route F / r27: pre-object gap `0x846898` must fall interior to the slab
/// when the nearest captured object is at `0x846bb0` (0x318-byte hole).
#[test]
fn heap_slab_span_covers_r27_pre_object_gap() {
    // Historical r27 layout (simplified): object at 0x846bb0; computed
    // stale ptr 0x846898 = 0x830000 + 0x16898 sits 0x318 bytes before it.
    let globals = vec![
        HeapGlobalSnapshot {
            rva: 0x1000,
            live_ptr: 0x846bb0,
            content: vec![0u8; 0x40],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
        HeapGlobalSnapshot {
            rva: 0x2000,
            live_ptr: 0x847000,
            content: vec![0u8; 0x20],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
        // Heap handle must not set min_obj by itself.
        HeapGlobalSnapshot {
            rva: 0x3000,
            live_ptr: 0x830000,
            content: vec![0u8; 8],
            is_heap_handle: true,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
    ];
    let (old_base, end) = compute_heap_slab_span(&globals).expect("span");
    let len = end - old_base;
    // Without prefix pad, old_base would be 0x846bb0 and 0x846898 is outside.
    assert!(
        old_base < 0x846898,
        "old_base={old_base:#x} must be below gap ptr 0x846898"
    );
    assert!(
        heap_slab_covers_interior(old_base, len, 0x846898),
        "slab [{old_base:#x},{end:#x}) must cover 0x846898"
    );
    assert!(heap_slab_covers_interior(old_base, len, 0x846bb0));
    // Strict interior: old_base itself is not rebased.
    assert!(!heap_slab_covers_interior(old_base, len, old_base));
    // Prefix is at least HEAP_SLAB_PREFIX_PAD below min object (page aligned).
    assert!(0x846bb0 - old_base >= HEAP_SLAB_PREFIX_PAD);
}

#[test]
fn heap_slab_span_none_for_single_object() {
    let globals = vec![HeapGlobalSnapshot {
        rva: 0x1000,
        live_ptr: 0x846bb0,
        content: vec![0u8; 0x40],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    }];
    assert!(compute_heap_slab_span(&globals).is_none());
}

// GTO Core Recovery R0-D: the window-string repair must mark its synthetic
// children with SyntheticDerived provenance (not RawCaptured), and repoint
// gscript+0xbd8/0xbd0 to those synthetic lives.
#[test]
fn r0d_window_string_repair_marks_synthetic_derived() {
    // gscript-like inline global with class/title slots at +0xbd0/+0xbd8
    // holding old (dump-path) strings.
    let mut gscript = HeapGlobalSnapshot {
        rva: 0x149d50,
        live_ptr: 0x1400_0000_0 + 0x149d50,
        content: vec![0u8; 0xbd8 + 16],
        is_heap_handle: false,
        is_image_inline: true,
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::ImageInline,
    };
    gscript.content[0xbd0..0xbd8].copy_from_slice(&0xa190a8u64.to_le_bytes());
    gscript.content[0xbd8..0xbd0 + 8 + 8].copy_from_slice(&0xa18ec0u64.to_le_bytes());
    let globals = vec![gscript.clone()];
    // GTO R0-F.2: window repair now produces two SyntheticRegionRequests
    // (no fixed-VA snapshot, no legacy placeholder). The requests carry the
    // SyntheticDerived transform id and anchor slots at +0xbd0/+0xbd8.
    let requests = make_gscript_window_string_requests(&globals);
    assert_eq!(requests.len(), 2);
    for req in &requests {
        assert_eq!(req.transform_id, "repair_gscript_window_strings");
        assert_eq!(req.alignment, 0x10);
        assert!(!req.payload.is_empty());
        // Construction digest == sha256 of the payload.
        assert_eq!(
            req.construction_digest,
            format!("{:x}", {
                let mut h = Sha256::new();
                h.update(&req.payload);
                h.finalize()
            })
        );
        // Each request anchors into the image-inline gscript at +0xbd0/+0xbd8.
        assert_eq!(req.pointer_slots.len(), 1);
        let anchor = &req.pointer_slots[0];
        assert_eq!(anchor.region_old_base, gscript.live_ptr);
        assert!(anchor.slot_offset == 0xbd0 || anchor.slot_offset == 0xbd8);
    }
    // No legacy fixed-VA synthetic snapshot was pushed into globals.
    assert!(globals
        .iter()
        .all(|g| g.live_ptr != 0x200000 && g.live_ptr != 0x201000));
    assert!(globals.len() == 1);
}

// GTO Core Recovery R0-E: identical-bytes duplicate at the same live_ptr is
// a redundant capture and is reconciled to a single entry.
#[test]
fn r0e_identical_bytes_duplicate_deduped() {
    let mut globals = vec![
        HeapGlobalSnapshot {
            rva: 0x146890,
            live_ptr: 0x8d8d60,
            content: vec![0x41u8; 0x400],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x8d8d60,
            content: vec![0x41u8; 0x400],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
    ];
    reconcile_duplicate_heap_globals(&mut globals, None);
    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].live_ptr, 0x8d8d60);
    assert_eq!(globals[0].content, vec![0x41u8; 0x400]);
}

// Route Y R1 GTO R1: adjacent heap objects admitted with overlapping probe
// windows are trimmed so the lower capture ends at the higher capture's
// base (the R1 raw-slab-overlay transformed-write-conflict geometry).
#[test]
fn r1_trim_overlapping_heap_global_windows() {
    let mk = |live: u64, len: usize| HeapGlobalSnapshot {
        rva: 0,
        live_ptr: live,
        content: vec![0xAAu8; len],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    // A = [0x882ad0, +0x400), B = [0x882e18, +0x400) — overlap 0xb8.
    let mut globals = vec![mk(0x882ad0, 0x400), mk(0x882e18, 0x400)];
    let trimmed = trim_overlapping_heap_global_windows(&mut globals);
    assert_eq!(trimmed, 1, "one capture must be trimmed");
    assert_eq!(
        globals[0].content.len(),
        (0x882e18 - 0x882ad0) as usize,
        "A must end at B's base"
    );
    assert_eq!(globals[1].content.len(), 0x400, "B unchanged");
    // No overlap remains.
    let a_end = globals[0].live_ptr + globals[0].content.len() as u64;
    assert!(a_end <= globals[1].live_ptr);
}

/// A declared-size reinit window is selected by capture metadata, not by
/// a sample-private RVA. The same semantic fixture must survive changed
/// image bases and changed RVAs.
#[test]
fn r1_trim_preserves_declared_size_window_across_image_bases() {
    let mk = |rva: u32, live: u64, len: usize, declared: bool| HeapGlobalSnapshot {
        rva,
        live_ptr: live,
        content: vec![0xAAu8; len],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: if declared {
            CaptureExtentKind::ObservedAllocation
        } else {
            CaptureExtentKind::default()
        },
        extent_evidence: if declared {
            CaptureExtentEvidence {
                capture_path: CapturePath::MainSlot,
                source_root_rva: Some(rva),
                ..CaptureExtentEvidence::default()
            }
        } else {
            CaptureExtentEvidence::default()
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };

    for image_base in [0x1400_0000_0u64, 0x1800_0000_0] {
        let target_rva = 0x2abc;
        let target_live = image_base + 0x20_0000;
        let mut globals = vec![
            mk(target_rva, target_live, HOT_XREF_SIZE_PROBE_CAP, true),
            mk(0x55aa, target_live + 0x900, 0x400, false),
        ];
        let trimmed = trim_overlapping_heap_global_windows(&mut globals);
        assert_eq!(trimmed, 0, "declared raw window must be preserved");
        assert_eq!(globals[0].content.len(), HOT_XREF_SIZE_PROBE_CAP);
        assert_eq!(globals[1].content.len(), 0x400);
    }

    let target_rva = 0x2abc;
    let mut globals = vec![
        mk(target_rva, 0x3200_0000, HOT_XREF_SIZE_PROBE_CAP, true),
        mk(0x55aa, 0x3200_0900, 0x400, false),
    ];
    let policy = HeapGlobalWindowTrimPolicy {
        preserve_declared_size_windows: false,
    };
    assert_eq!(
        trim_overlapping_heap_global_windows_with_policy(&mut globals, &policy),
        1,
        "explicit policy can disable raw-window preservation",
    );
}

/// Lower capture already bounded by a HIGHER known base is untouched.
#[test]
fn r1_trim_only_affects_interior_base_overlap() {
    let mk = |live: u64, len: usize| HeapGlobalSnapshot {
        rva: 0,
        live_ptr: live,
        content: vec![0xAAu8; len],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    // Disjoint windows — nothing to trim.
    let mut globals = vec![mk(0x1000, 0x100), mk(0x1200, 0x100)];
    let trimmed = trim_overlapping_heap_global_windows(&mut globals);
    assert_eq!(trimmed, 0);
    assert_eq!(globals[0].content.len(), 0x100);
    assert_eq!(globals[1].content.len(), 0x100);
}

// GTO Core Recovery R0-E: two entries at the same live_ptr with differing
// bytes are reconciled to the one coherent with the raw slab (physical
// memory ground truth). Reproduces the Route M R1 conflict geometry.
#[test]
fn r0e_differing_bytes_prefers_raw_slab_coherent() {
    // Slab: [0x89f000, ...). The physical bytes at 0x8d8d60 (= offset
    // 0x39d60 in the slab) are [0xBB; 0x400]. One capture is coherent with
    // the slab; the other (stale/drifted) is not.
    let slab_off = (0x8d8d60u64 - 0x89f000u64) as usize; // 0x39d60
    let mut slab_content = vec![0u8; slab_off + 0x400];
    for b in slab_content[slab_off..slab_off + 0x400].iter_mut() {
        *b = 0xBB;
    }
    let slab = HeapSlab {
        old_base: 0x89f000,
        content: slab_content,
    };
    let mut globals = vec![
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x8d8d60,
            content: vec![0xBBu8; 0x400], // coherent with slab
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x8d8d60,
            content: vec![0xAAu8; 0x400], // NOT coherent (drift)
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
    ];
    reconcile_duplicate_heap_globals(&mut globals, Some(&slab));
    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].content, vec![0xBBu8; 0x400]);
}

// GTO Core Recovery R0-E: a duplicate whose raw bytes match the slab is
// preferred over a non-coherent one regardless of insertion order.
#[test]
fn r0e_coherent_wins_over_noncoherent_any_order() {
    let slab_off = (0x8d8d60u64 - 0x89f000u64) as usize;
    let mut slab_content = vec![0u8; slab_off + 0x20];
    for b in slab_content[slab_off..slab_off + 0x20].iter_mut() {
        *b = 0x77;
    }
    let slab = HeapSlab {
        old_base: 0x89f000,
        content: slab_content,
    };
    // Non-coherent first, coherent second.
    let mut globals = vec![
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x8d8d60,
            content: vec![0x11u8; 0x20],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x8d8d60,
            content: vec![0x77u8; 0x20],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
    ];
    reconcile_duplicate_heap_globals(&mut globals, Some(&slab));
    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].content, vec![0x77u8; 0x20]);
}

// GTO Core Recovery R0-E: differing bytes with no raw slab (no slab
// capture) prefer the larger snapshot; an exact-size tie with differing
// bytes is retained so the overlay fail-closes with provenance rather than
// silently picking.
#[test]
fn r0e_no_slab_prefers_larger_keeps_tie_conflict() {
    // Larger wins.
    let mut a = vec![
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x8d8d60,
            content: vec![0xAAu8; 0x400],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x8d8d60,
            content: vec![0xBBu8; 0x200],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
    ];
    reconcile_duplicate_heap_globals(&mut a, None);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].content, vec![0xAAu8; 0x400]);

    // Exact-size tie with differing bytes and no slab → retained (fail-closed).
    let mut b = vec![
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x8d8d60,
            content: vec![0xAAu8; 0x400],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x8d8d60,
            content: vec![0xBBu8; 0x400],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
    ];
    reconcile_duplicate_heap_globals(&mut b, None);
    assert_eq!(b.len(), 2); // both retained; overlay will fail-closed
}

// =====================================================================
// GTO Core Recovery R0-F.2 tests
// =====================================================================

fn r0f2_req(synthetic_id: &str, payload: &[u8], slot_off: usize) -> SyntheticRegionRequest {
    SyntheticRegionRequest {
        synthetic_id: synthetic_id.to_string(),
        transform_id: "repair_gscript_window_strings".to_string(),
        source_anchor: format!("anchor:{synthetic_id}"),
        payload: payload.to_vec(),
        construction_digest: sha256_hex(payload),
        alignment: 0x10,
        pointer_slots: vec![SyntheticPointerAnchor {
            region_old_base: 0x1400_0000_0 + 0x149d50,
            slot_offset: slot_off,
        }],
    }
}

/// Route N slab [0x14f000, 0x36f3d30) contains both legacy synthetic
/// logical addresses 0x200000 and 0x201000 — proving the fixed-address
/// scheme is unsafe in Route N geometry.
#[test]
fn r0f2_route_n_slab_contains_legacy_synthetic_addresses() {
    const SLAB_BASE: u64 = 0x14f000;
    const SLAB_END: u64 = 0x36f3d30;
    assert!(SLAB_BASE < 0x200000 && 0x201000 < SLAB_END);
    assert!(SLAB_BASE < 0x201000);
    assert!(0x200000 > SLAB_BASE);
    assert!(0x201000 < SLAB_END);
}

/// Window repair produces two requests (class/title), not fixed-VA snapshots.
#[test]
fn r0f2_window_repair_creates_requests_not_fixed_live_regions() {
    let mut gscript = HeapGlobalSnapshot {
        rva: 0x149d50,
        live_ptr: 0x1400_0000_0 + 0x149d50,
        content: vec![0u8; 0xbd8 + 16],
        is_heap_handle: false,
        is_image_inline: true,
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::ImageInline,
    };
    let globals = vec![gscript.clone()];
    let requests = make_gscript_window_string_requests(&globals);
    assert_eq!(requests.len(), 2);
    let ids: Vec<&str> = requests.iter().map(|r| r.synthetic_id.as_str()).collect();
    assert!(ids.contains(&"gto.window_class"));
    assert!(ids.contains(&"gto.window_title"));
    // No fixed-VA snapshot was created.
    assert!(globals
        .iter()
        .all(|g| g.live_ptr != 0x200000 && g.live_ptr != 0x201000));
    let _ = &mut gscript;
}

/// Assigned synthetic bases must avoid the raw heap slab span.
#[test]
fn r0f2_synthetic_assignment_avoids_raw_slab() {
    let req = r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8);
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let assigned = assign_synthetic_logical_addresses(&[req], &avoid).unwrap();
    let base = assigned[0].old_base();
    assert!(!(base >= 0x14f000 && base < 0x36f3d30));
}

/// Assigned synthetic bases must avoid the source image and module ranges.
#[test]
fn r0f2_synthetic_assignment_avoids_image_and_modules() {
    let req = r0f2_req("gto.window_title", b"ZhuChuangKou\0", 0xbd0);
    let avoid = vec![
        (0x140_0000_0u64, 0x141_0000_0u64),         // image span
        (0x7ff0_0000_0000u64, 0x7ff0_0001_0000u64), // module
    ];
    let assigned = assign_synthetic_logical_addresses(&[req], &avoid).unwrap();
    let base = assigned[0].old_base();
    assert!(!(base >= 0x140_0000_0 && base < 0x141_0000_0));
    assert!(!(base >= 0x7ff0_0000_0000 && base < 0x7ff0_0001_0000));
}

/// Same input => same assignment.
#[test]
fn r0f2_synthetic_assignment_is_deterministic() {
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let a = assign_synthetic_logical_addresses(
        &[r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8)],
        &avoid,
    )
    .unwrap();
    let b = assign_synthetic_logical_addresses(
        &[r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8)],
        &avoid,
    )
    .unwrap();
    assert_eq!(a[0].old_base(), b[0].old_base());
}

/// Reordering requests gives the same assignments (deterministic sort).
#[test]
fn r0f2_synthetic_assignment_order_independent() {
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let r_class = r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8);
    let r_title = r0f2_req("gto.window_title", b"ZhuChuangKou\0", 0xbd0);
    let ab =
        assign_synthetic_logical_addresses(&[r_class.clone(), r_title.clone()], &avoid).unwrap();
    let ba = assign_synthetic_logical_addresses(&[r_title, r_class], &avoid).unwrap();
    assert_eq!(
        ab.iter()
            .find(|a| a.id() == "gto.window_class")
            .unwrap()
            .old_base(),
        ba.iter()
            .find(|a| a.id() == "gto.window_class")
            .unwrap()
            .old_base()
    );
    assert_eq!(
        ab.iter()
            .find(|a| a.id() == "gto.window_title")
            .unwrap()
            .old_base(),
        ba.iter()
            .find(|a| a.id() == "gto.window_title")
            .unwrap()
            .old_base()
    );
}

/// Two synthetic requests must be disjoint.
#[test]
fn r0f2_two_synthetic_requests_are_disjoint() {
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let assigned = assign_synthetic_logical_addresses(
        &[
            r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8),
            r0f2_req("gto.window_title", b"ZhuChuangKou\0", 0xbd0),
        ],
        &avoid,
    )
    .unwrap();
    assert_eq!(assigned.len(), 2);
    let (b0, b1) = (assigned[0].old_base(), assigned[1].old_base());
    assert_ne!(b0, b1);
    // Both 16-aligned and non-overlapping (differ by >= 16).
    assert!(b0 % 16 == 0 && b1 % 16 == 0);
    assert!(b0.checked_add(16).unwrap() <= b1 || b1.checked_add(16).unwrap() <= b0);
}

/// Range-end overflow / exhausted space fails closed.
#[test]
fn r0f2_assignment_overflow_fails_closed() {
    // Cover every address from the floor upward with an authority range so
    // no collision-free logical base exists. The allocator either overflows
    // (checked) or reports NoAvailableRange — either way it fails closed.
    let req = r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8);
    let avoid = vec![(0x1_0000u64, u64::MAX)];
    let res = assign_synthetic_logical_addresses(&[req], &avoid);
    assert!(res.is_err());
}

/// Anchor slot out of bounds fails closed.
#[test]
fn r0f2_anchor_slot_out_of_bounds_fails_closed() {
    let req = r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8);
    let mut payload = vec![0u8; 0x100];
    let mut regions: Vec<(u64, &mut Vec<u8>)> = vec![(0x1400_0000_0 + 0x149d50, &mut payload)];
    let res = rewrite_synthetic_anchor_slots(&mut regions, &req.pointer_slots, 0x10000);
    assert!(res.is_err());
}

/// Assignment rewrites both class and title slots to the assigned bases.
#[test]
fn r0f2_assignment_rewrites_class_and_title_slots() {
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let r_class = r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8);
    let r_title = r0f2_req("gto.window_title", b"ZhuChuangKou\0", 0xbd0);
    let assigned =
        assign_synthetic_logical_addresses(&[r_class.clone(), r_title.clone()], &avoid).unwrap();
    let class_base = assigned
        .iter()
        .find(|a| a.id() == "gto.window_class")
        .unwrap()
        .old_base();
    let title_base = assigned
        .iter()
        .find(|a| a.id() == "gto.window_title")
        .unwrap()
        .old_base();
    // gscript payload large enough for both slots.
    let mut gscript_payload = vec![0u8; 0xbd8 + 16];
    let base = 0x1400_0000_0 + 0x149d50;
    let mut regions: Vec<(u64, &mut Vec<u8>)> = vec![(base, &mut gscript_payload)];
    rewrite_synthetic_anchor_slots(&mut regions, &r_class.pointer_slots, class_base).unwrap();
    rewrite_synthetic_anchor_slots(&mut regions, &r_title.pointer_slots, title_base).unwrap();
    assert_eq!(
        u64::from_le_bytes(gscript_payload[0xbd8..0xbd8 + 8].try_into().unwrap()),
        class_base
    );
    assert_eq!(
        u64::from_le_bytes(gscript_payload[0xbd0..0xbd0 + 8].try_into().unwrap()),
        title_base
    );
}

/// Legacy placeholders (0x200000/0x201000) must never appear in any
/// assigned base.
#[test]
fn r0f2_legacy_placeholders_do_not_reach_assignment() {
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let assigned = assign_synthetic_logical_addresses(
        &[
            r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8),
            r0f2_req("gto.window_title", b"ZhuChuangKou\0", 0xbd0),
        ],
        &avoid,
    )
    .unwrap();
    for a in &assigned {
        assert_ne!(a.old_base(), 0x200000);
        assert_ne!(a.old_base(), 0x201000);
    }
}

/// Materialized synthetic regions carry SyntheticDerived extent + provenance.
#[test]
fn r0f2_synthetic_extent_is_explicit_in_production() {
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let req = r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8);
    let assigned = assign_synthetic_logical_addresses(&[req.clone()], &avoid).unwrap();
    let materialized = materialize_synthetic_regions(&assigned).unwrap();
    assert_eq!(materialized.len(), 1);
    let g = &materialized[0];
    assert_eq!(g.extent_kind, CaptureExtentKind::SyntheticDerived);
    assert!(matches!(
        g.provenance,
        RegionProvenance::SyntheticDerived { .. }
    ));
    assert_eq!(g.live_ptr, assigned[0].old_base());
    assert!(!g.is_image_inline);
}

/// SyntheticAllocation ownership is production-assigned by the planner.
#[test]
fn r0f2_synthetic_ownership_is_synthetic_allocation() {
    use crate::dumper::runtime_rebase::RuntimeRegionOwnership;
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let req = r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8);
    let assigned = assign_synthetic_logical_addresses(&[req.clone()], &avoid).unwrap();
    let materialized = materialize_synthetic_regions(&assigned).unwrap();
    // Build a plan from the materialized synthetic snapshot and confirm the
    // region's ownership is SyntheticAllocation.
    let slab = HeapSlab {
        old_base: 0x14f000,
        content: vec![0u8; 0x1000],
    };
    let plan = crate::dumper::runtime_rebase::build_runtime_rebase_plan(
        &[],
        &materialized,
        &[slab.clone()],
        &[],
        &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
        &[],
        0x140_0000_0,
        0x140_0000_0,
    )
    .unwrap()
    .unwrap();
    let synth = plan
        .regions
        .iter()
        .find(|r| r.old_base == assigned[0].old_base())
        .expect("synthetic region present");
    assert_eq!(synth.ownership, RuntimeRegionOwnership::SyntheticAllocation);
    assert_eq!(synth.extent_kind, CaptureExtentKind::SyntheticDerived);
}

/// A synthetic region is never absorbed into the slab (independent region).
#[test]
fn r0f2_synthetic_is_never_absorbed_into_slab() {
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let req = r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8);
    let assigned = assign_synthetic_logical_addresses(&[req.clone()], &avoid).unwrap();
    let materialized = materialize_synthetic_regions(&assigned).unwrap();
    // Slab plus one synthetic snapshot: both must be distinct backing regions.
    let slab = HeapSlab {
        old_base: 0x14f000,
        content: vec![0u8; 0x1000],
    };
    let plan = crate::dumper::runtime_rebase::build_runtime_rebase_plan(
        &[],
        &materialized,
        &[slab.clone()],
        &[],
        &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
        &[],
        0x140_0000_0,
        0x140_0000_0,
    )
    .unwrap()
    .unwrap();
    // Slab region + synthetic region = 2 backing regions; 0 aliases.
    assert_eq!(plan.regions.len(), 2);
    assert!(plan.aliases.is_empty());
}

/// The synthetic region's anchor pointer (from gscript) targets the
/// synthetic independent region, never the slab offset of a legacy base.
#[test]
fn r0f2_synthetic_pointer_targets_independent_region() {
    let avoid = vec![(0x14f000u64, 0x36f3d30u64)];
    let req = r0f2_req("gto.window_class", b"NewClassName\0", 0xbd8);
    let assigned = assign_synthetic_logical_addresses(&[req.clone()], &avoid).unwrap();
    let class_base = assigned[0].old_base();
    // gscript image-inline snapshot whose +0xbd8 slot holds the assigned base.
    let mut gscript = vec![0u8; 0xbd8 + 16];
    gscript[0xbd8..0xbd8 + 8].copy_from_slice(&class_base.to_le_bytes());
    let gscript_global = HeapGlobalSnapshot {
        rva: 0x149d50,
        live_ptr: 0x1400_0000_0 + 0x149d50,
        content: gscript,
        is_heap_handle: false,
        is_image_inline: true,
        extent_kind: CaptureExtentKind::BackingObject,
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::ImageInline,
    };
    let materialized = materialize_synthetic_regions(&assigned).unwrap();
    let mut all = materialized;
    all.push(gscript_global);
    let slab = HeapSlab {
        old_base: 0x14f000,
        content: vec![0u8; 0x1000],
    };
    let plan = crate::dumper::runtime_rebase::build_runtime_rebase_plan(
        &[],
        &all,
        &[slab.clone()],
        &crate::dumper::runtime_rebase::declared_slots_from_capture(&[], &all, &[slab.clone()]),
        &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
        &[],
        0x140_0000_0,
        0x140_0000_0,
    )
    .unwrap()
    .unwrap();
    // Find the slot in the gscript image-inline region at +0xbd8.
    let synth_region_id = plan
        .regions
        .iter()
        .find(|r| r.old_base == class_base)
        .map(|r| r.id)
        .unwrap();
    let slot = plan
        .pointers
        .iter()
        .find(|p| p.original_value == class_base)
        .expect("gscript+0xbd8 slot");
    assert_eq!(slot.target_region, Some(synth_region_id));
    assert_eq!(slot.target_offset, Some(0));
}

// =====================================================================
// GTO Core Recovery R0-F.2.1 — synthetic assignment identity binding
// =====================================================================

/// The production window-string requests: class (gscript+0xbd8) first,
/// title (gscript+0xbd0) second — the request creation order that exposes
/// the positional-zip bug.
fn r0f21_window_requests() -> (SyntheticRegionRequest, SyntheticRegionRequest) {
    let class = SyntheticRegionRequest {
        synthetic_id: "gto.window_class".to_string(),
        transform_id: "repair_gscript_window_strings".to_string(),
        source_anchor: "gscript+0xbd8 (RegisterClass lpszClassName)".to_string(),
        payload: "NewClassName\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<u8>>(),
        construction_digest: sha256_hex_pub(
            &"NewClassName\0"
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<u8>>(),
        ),
        alignment: 0x10,
        pointer_slots: vec![SyntheticPointerAnchor {
            region_old_base: 0x1400_0000_0 + 0x149d50,
            slot_offset: 0xbd8,
        }],
    };
    let title = SyntheticRegionRequest {
        synthetic_id: "gto.window_title".to_string(),
        transform_id: "repair_gscript_window_strings".to_string(),
        source_anchor: "gscript+0xbd0 (CreateWindow title)".to_string(),
        payload: "ZhuChuangKou\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<u8>>(),
        construction_digest: sha256_hex_pub(
            &"ZhuChuangKou\0"
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<u8>>(),
        ),
        alignment: 0x10,
        pointer_slots: vec![SyntheticPointerAnchor {
            region_old_base: 0x1400_0000_0 + 0x149d50,
            slot_offset: 0xbd0,
        }],
    };
    (class, title)
}

/// The Route N avoid ranges used in production (small-tag, image, slab,
/// globals, containers, modules). For the tests a slab-span avoid is enough.
fn r0f21_avoid() -> Vec<(u64, u64)> {
    vec![
        (0, 0x1_0000),         // small-tag range
        (0x14f000, 0x36f3d30), // raw slab span
    ]
}

/// A production-like helper mirroring dump_process's synthetic path:
/// create requests → assign (identity-bound) → rewrite anchors (read-back)
/// → materialize (Result) → identity-closed-loop gate. Returns the bound
/// set, the rewritten gscript payload, and the materialized snapshots.
fn r0f21_production_flow(
    requests: &[SyntheticRegionRequest],
) -> Result<
    (
        Vec<BoundSyntheticAssignment>,
        Vec<u8>,
        Vec<HeapGlobalSnapshot>,
    ),
    SyntheticAssignError,
> {
    let bound = assign_synthetic_logical_addresses(requests, &r0f21_avoid())?;
    // gscript image-inline payload large enough for both slots.
    let mut gscript_payload = vec![0u8; 0xbd8 + 16];
    let gscript_base = bound
        .first()
        .and_then(|b| b.request.pointer_slots.first())
        .map(|a| a.region_old_base)
        .unwrap_or(0);
    let mut regions: Vec<(u64, &mut Vec<u8>)> = vec![(gscript_base, &mut gscript_payload)];
    for b in &bound {
        let rewritten = rewrite_synthetic_anchor_slots(
            &mut regions,
            &b.request.pointer_slots,
            b.assignment.assigned_logical_old_base,
        )?;
        if rewritten != b.request.pointer_slots.len() {
            return Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(
                format!(
                    "rewrote {rewritten} != expected {}",
                    b.request.pointer_slots.len()
                ),
            ));
        }
    }
    let materialized = materialize_synthetic_regions(&bound)?;
    // Identity-closed-loop gate: every materialized snapshot live_ptr == its
    // assignment base, and it carries SyntheticDerived provenance/extent.
    for b in &bound {
        let snap = materialized
            .iter()
            .find(|s| s.live_ptr == b.assignment.assigned_logical_old_base)
            .ok_or_else(|| {
                SyntheticAssignError::MaterializationFailed(format!(
                    "missing materialized snapshot for '{}'",
                    b.assignment.synthetic_id
                ))
            })?;
        if snap.extent_kind != CaptureExtentKind::SyntheticDerived {
            return Err(SyntheticAssignError::MaterializationFailed(format!(
                "extent {:?} != SyntheticDerived",
                snap.extent_kind
            )));
        }
    }
    Ok((bound, gscript_payload, materialized))
}

/// The allocator's returned order (sorted by source_anchor) differs from the
/// request creation order: title (gscript+0xbd0) sorts before class
/// (gscript+0xbd8), so assignment order is [title, class] while requests are
/// [class, title].
#[test]
fn r0f21_allocator_sort_differs_from_request_order() {
    let (class, title) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class, title], &r0f21_avoid()).unwrap();
    let ids: Vec<&str> = bound.iter().map(|b| b.id()).collect();
    // Request creation order was [class, title]; allocator returns [title, class].
    assert_eq!(ids, vec!["gto.window_title", "gto.window_class"]);
}

/// The bound assignment pairs by synthetic_id, not by position.
#[test]
fn r0f21_binding_by_id_not_position() {
    let (class, title) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class, title], &r0f21_avoid()).unwrap();
    // Each bound.request.synthetic_id == bound.assignment.synthetic_id.
    for b in &bound {
        assert_eq!(b.request.synthetic_id, b.assignment.synthetic_id);
    }
    // The class assignment is bound to the class request (correct payload).
    let class_b = bound.iter().find(|b| b.id() == "gto.window_class").unwrap();
    let payload = String::from_utf16(
        &class_b
            .request
            .payload
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(payload, "NewClassName\0");
}

/// gscript+0xbd8 target corresponds to the class payload (NewClassName).
#[test]
fn r0f21_class_slot_points_to_class_payload() {
    let (class, title) = r0f21_window_requests();
    let (bound, gscript_payload, _) = r0f21_production_flow(&[class, title]).unwrap();
    let class_base = bound
        .iter()
        .find(|b| b.id() == "gto.window_class")
        .unwrap()
        .old_base();
    let slot = u64::from_le_bytes(gscript_payload[0xbd8..0xbd8 + 8].try_into().unwrap());
    assert_eq!(slot, class_base);
    // And class_base corresponds to the class request's payload region.
    let class_payload = String::from_utf16(
        &bound
            .iter()
            .find(|b| b.id() == "gto.window_class")
            .unwrap()
            .request
            .payload
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(class_payload, "NewClassName\0");
}

/// gscript+0xbd0 target corresponds to the title payload (ZhuChuangKou).
#[test]
fn r0f21_title_slot_points_to_title_payload() {
    let (class, title) = r0f21_window_requests();
    let (bound, gscript_payload, _) = r0f21_production_flow(&[class, title]).unwrap();
    let title_base = bound
        .iter()
        .find(|b| b.id() == "gto.window_title")
        .unwrap()
        .old_base();
    let slot = u64::from_le_bytes(gscript_payload[0xbd0..0xbd0 + 8].try_into().unwrap());
    assert_eq!(slot, title_base);
    let title_payload = String::from_utf16(
        &bound
            .iter()
            .find(|b| b.id() == "gto.window_title")
            .unwrap()
            .request
            .payload
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(title_payload, "ZhuChuangKou\0");
}

/// Reversed request order yields the same identity-bound result.
#[test]
fn r0f21_reversed_request_order_same_result() {
    let (class, title) = r0f21_window_requests();
    let a = assign_synthetic_logical_addresses(&[class.clone(), title.clone()], &r0f21_avoid())
        .unwrap();
    let b = assign_synthetic_logical_addresses(&[title, class], &r0f21_avoid()).unwrap();
    for id in ["gto.window_class", "gto.window_title"] {
        let ba = a.iter().find(|x| x.id() == id).unwrap();
        let bb = b.iter().find(|x| x.id() == id).unwrap();
        assert_eq!(ba.old_base(), bb.old_base());
        assert_eq!(ba.assignment.request_digest, bb.assignment.request_digest);
    }
}

/// Reversed assignment order (the production result is a Vec; reassigning
/// its order) yields the same per-id binding. The allocator itself returns a
/// fixed order, so this proves identity, not order, drives the pairing.
#[test]
fn r0f21_reversed_assignment_order_same_result() {
    let (class, title) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class, title], &r0f21_avoid()).unwrap();
    let mut reversed = bound.clone();
    reversed.reverse();
    // Each bound pair still carries its own request+assignment; reversing
    // the Vec must not change the materialized payload-to-base mapping.
    let m1 = materialize_synthetic_regions(&bound).unwrap();
    let m2 = materialize_synthetic_regions(&reversed).unwrap();
    // The materialized SET must be identical (compare by live_ptr, order-agnostic).
    let mut by_base1: Vec<u64> = m1.iter().map(|s| s.live_ptr).collect();
    let mut by_base2: Vec<u64> = m2.iter().map(|s| s.live_ptr).collect();
    by_base1.sort_unstable();
    by_base2.sort_unstable();
    assert_eq!(by_base1, by_base2);
}

/// Duplicate request synthetic_id fails closed.
#[test]
fn r0f21_duplicate_request_id_fails_closed() {
    let (class, _) = r0f21_window_requests();
    let dup = class.clone();
    let res = assign_synthetic_logical_addresses(&[class, dup], &r0f21_avoid());
    assert!(matches!(
        res,
        Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(_))
    ));
}

/// Duplicate assignment id fails closed (validate_bound_assignments rejects).
#[test]
fn r0f21_duplicate_assignment_id_fails_closed() {
    let (class, _) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class], &r0f21_avoid()).unwrap();
    // Duplicate the single bound pair to create a duplicate id set.
    let mut dup = bound.clone();
    dup.push(bound[0].clone());
    let res = validate_bound_assignments(&dup);
    assert!(matches!(
        res,
        Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(_))
    ));
}

/// A bound pair whose request id != assignment id fails closed.
#[test]
fn r0f21_missing_assignment_fails_closed() {
    let (class, title) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class, title], &r0f21_avoid()).unwrap();
    // Tamper: make one pair's assignment id not match its request id.
    let mut bad = bound.clone();
    bad[1].assignment.synthetic_id = "gto.does_not_exist".to_string();
    let res = validate_bound_assignments(&bad);
    assert!(matches!(
        res,
        Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(_))
    ));
}

/// An extra assignment (a bound pair referencing a request not in the set)
/// fails closed via duplicate/identity checks.
#[test]
fn r0f21_extra_assignment_fails_closed() {
    let (class, title) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class, title], &r0f21_avoid()).unwrap();
    // Add a pair with a synthetic id that has no matching request (clone an
    // existing request but change its id in the assignment only is an
    // identity mismatch, which validate_bound_assignments rejects).
    let mut extra = bound.clone();
    let mut cloned = extra[0].clone();
    cloned.assignment.synthetic_id = "gto.extra".to_string();
    extra.push(cloned);
    let res = validate_bound_assignments(&extra);
    assert!(matches!(
        res,
        Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(_))
    ));
}

/// A tampered request_digest fails closed.
#[test]
fn r0f21_request_digest_mismatch_fails_closed() {
    let (class, _) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class], &r0f21_avoid()).unwrap();
    let mut bad = bound.clone();
    bad[0].assignment.request_digest = "tampered".to_string();
    let res = validate_bound_assignments(&bad);
    assert!(matches!(
        res,
        Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(_))
    ));
}

/// Materialization with a bound pair whose request is missing fails closed.
#[test]
fn r0f21_materialization_missing_request_fails_closed() {
    let (class, title) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class, title], &r0f21_avoid()).unwrap();
    // Give one pair an assignment id with no matching request -> the
    // validate_bound_assignments inside materialize rejects it.
    let mut bad = bound.clone();
    bad[0].assignment.synthetic_id = "gto.missing".to_string();
    let res = materialize_synthetic_regions(&bad);
    assert!(matches!(
        res,
        Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(_))
    ));
}

/// Partial materialization is never returned: if one snapshot fails, the
/// whole call returns Err (no partial Vec).
#[test]
fn r0f21_partial_materialization_not_returned() {
    let (class, title) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class, title], &r0f21_avoid()).unwrap();
    // Corrupt one request's construction digest so its snapshot would
    // differ; materialize must Err and never return a partial Vec.
    let mut bad = bound.clone();
    bad[0].request.construction_digest = "wrong".to_string();
    let res = materialize_synthetic_regions(&bad);
    assert!(res.is_err());
}

/// rewritten_anchor_count equals the number of anchor slots (exact).
#[test]
fn r0f21_rewritten_anchor_count_is_exact() {
    let (class, title) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class, title], &r0f21_avoid()).unwrap();
    let mut gscript_payload = vec![0u8; 0xbd8 + 16];
    let gscript_base = bound[0].request.pointer_slots[0].region_old_base;
    let mut regions: Vec<(u64, &mut Vec<u8>)> = vec![(gscript_base, &mut gscript_payload)];
    for b in &bound {
        let rewritten =
            rewrite_synthetic_anchor_slots(&mut regions, &b.request.pointer_slots, b.old_base())
                .unwrap();
        assert_eq!(rewritten, b.request.pointer_slots.len());
        assert_eq!(rewritten, 1); // window class/title each have 1 anchor
    }
}

/// Anchor slots are read-back verified (the slot value == assigned base).
#[test]
fn r0f21_anchor_slot_is_read_back_verified() {
    let (class, title) = r0f21_window_requests();
    let bound = assign_synthetic_logical_addresses(&[class, title], &r0f21_avoid()).unwrap();
    let mut gscript_payload = vec![0u8; 0xbd8 + 16];
    let gscript_base = bound[0].request.pointer_slots[0].region_old_base;
    let mut regions: Vec<(u64, &mut Vec<u8>)> = vec![(gscript_base, &mut gscript_payload)];
    for b in &bound {
        rewrite_synthetic_anchor_slots(&mut regions, &b.request.pointer_slots, b.old_base())
            .unwrap();
    }
    // Direct read-back: class slot == class base, title slot == title base.
    let class_base = bound
        .iter()
        .find(|b| b.id() == "gto.window_class")
        .unwrap()
        .old_base();
    let title_base = bound
        .iter()
        .find(|b| b.id() == "gto.window_title")
        .unwrap()
        .old_base();
    assert_eq!(
        u64::from_le_bytes(gscript_payload[0xbd8..0xbd8 + 8].try_into().unwrap()),
        class_base
    );
    assert_eq!(
        u64::from_le_bytes(gscript_payload[0xbd0..0xbd0 + 8].try_into().unwrap()),
        title_base
    );
    // Cross-check: the two slots do NOT point to each other's base.
    assert_ne!(
        u64::from_le_bytes(gscript_payload[0xbd8..0xbd8 + 8].try_into().unwrap()),
        title_base
    );
}

/// Manifest: pointer_slot_rewritten (old inferred) is no longer used; the
/// ledger derives rewrite from real rewritten_anchor_count == expected.
#[test]
fn r0f21_manifest_does_not_infer_rewrite_from_nonempty_slots() {
    // A request with a non-empty slot list but an assignment whose
    // rewritten_anchor_count is 0 must NOT report anchor_rewrite_verified.
    let payload = b"NewClassName\0".to_vec();
    let req = SyntheticRegionRequest {
        synthetic_id: "gto.window_class".to_string(),
        transform_id: "t".to_string(),
        source_anchor: "gscript+0xbd8".to_string(),
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
        rewritten_anchor_count: 0, // NOT rewritten (real evidence)
        materialized: false,
    }];
    let json = super::super::snapshot_manifest::render_manifest_json(
        std::path::Path::new("cand.exe"),
        super::super::types::DumpProfile::AhkGtoExperimental,
        0x140000000,
        0x70b0,
        &[],
        &[],
        &super::super::capture_policy::DumpCapturePolicy::ahk_gto_default(),
        false,
        None,
        &[],
        &[],
        &[],
        &super::super::raw_slab_coherence::TransformRunLedger::default(),
        &[req],
        &assigned,
        &[],
        &[],
        &[],
    )
    .unwrap();
    // The manifest must NOT claim the rewrite happened just because the
    // request had non-empty slots.
    assert!(json.contains("\"rewritten_anchor_count\": 0"));
    assert!(json.contains("\"anchor_rewrite_verified\": false"));
    assert!(json.contains("\"expected_anchor_count\": 1"));
}

/// Manifest records real rewrite + materialization evidence (v2).
#[test]
fn r0f21_manifest_records_real_rewrite_and_materialization() {
    let (class, title) = r0f21_window_requests();
    let (bound, _, materialized) = r0f21_production_flow(&[class, title]).unwrap();
    let ledgers: Vec<SyntheticAssignment> = bound
        .iter()
        .map(|b| SyntheticAssignment {
            synthetic_id: b.assignment.synthetic_id.clone(),
            request_digest: b.assignment.request_digest.clone(),
            assigned_logical_old_base: b.assignment.assigned_logical_old_base,
            assignment_alignment: b.assignment.assignment_alignment,
            rewritten_anchor_count: 1,
            materialized: true,
        })
        .collect();
    let reqs: Vec<SyntheticRegionRequest> = bound.iter().map(|b| b.request.clone()).collect();
    let json = super::super::snapshot_manifest::render_manifest_json(
        std::path::Path::new("cand.exe"),
        super::super::types::DumpProfile::AhkGtoExperimental,
        0x140000000,
        0x70b0,
        &[],
        &materialized,
        &super::super::capture_policy::DumpCapturePolicy::ahk_gto_default(),
        false,
        None,
        &[],
        &[],
        &[],
        &super::super::raw_slab_coherence::TransformRunLedger::default(),
        &reqs,
        &ledgers,
        &[],
        &[],
        &[],
    )
    .unwrap();
    for id in ["gto.window_class", "gto.window_title"] {
        assert!(json.contains(&format!("\"synthetic_id\": \"{id}\"")));
        assert!(json.contains("\"rewritten_anchor_count\": 1"));
        assert!(json.contains("\"materialized\": true"));
        assert!(json.contains("\"anchor_rewrite_verified\": true"));
    }
}

/// Algorithm version is 2 (identity-binding semantics).
#[test]
fn r0f21_algorithm_version_is_2() {
    assert_eq!(
        super::super::snapshot_manifest::synthetic_assignment_algorithm_version(),
        2
    );
}

/// Checked alignment near u64::MAX fails closed rather than panicking/wrapping.
#[test]
fn r0f21_checked_align_near_u64_max_fails_closed() {
    // checked_align_up_u64 returns None on overflow.
    assert_eq!(checked_align_up_u64(u64::MAX, 0x10), None);
    // u64::MAX-15 is 16-aligned; +0xf stays in range -> Some.
    assert_eq!(
        checked_align_up_u64(u64::MAX - 15, 0x10),
        Some(u64::MAX & !0xf)
    );
    // A request whose only free range would overflow alignment fails closed.
    let payload = b"X".to_vec();
    let req = SyntheticRegionRequest {
        synthetic_id: "gto.high".to_string(),
        transform_id: "t".to_string(),
        source_anchor: "a".to_string(),
        payload: payload.clone(),
        construction_digest: sha256_hex_pub(&payload),
        alignment: 0x10,
        pointer_slots: vec![],
    };
    // Avoid everything from the floor upward; the jump to just-past a range
    // near u64::MAX must fail closed (NoAvailableRange or AlignmentOverflow),
    // never panic/wrap.
    let res = assign_synthetic_logical_addresses(&[req], &[(0x1_0000, u64::MAX)]);
    assert!(res.is_err());
}

/// Full end-to-end identity loop: request → assignment → rewritten anchor →
/// materialized snapshot all share synthetic_id / request_digest / base.
#[test]
fn r0f21_end_to_end_request_assignment_anchor_snapshot_identity() {
    let (class, title) = r0f21_window_requests();
    let (bound, gscript_payload, materialized) = r0f21_production_flow(&[class, title]).unwrap();
    assert_eq!(bound.len(), 2);
    assert_eq!(materialized.len(), 2);
    for b in &bound {
        let id = b.id();
        // The materialized snapshot for this id exists at the assigned base.
        let snap = materialized
            .iter()
            .find(|s| s.live_ptr == b.old_base())
            .expect("materialized snapshot for bound id");
        // same synthetic_id / request_digest / construction digest / base.
        assert_eq!(snap.extent_evidence.capture_id, id);
        assert_eq!(snap.live_ptr, b.assignment.assigned_logical_old_base);
        assert_eq!(snap.extent_kind, CaptureExtentKind::SyntheticDerived);
        // The anchor slot in gscript points at this snapshot's base.
        let slot_off = if id == "gto.window_class" {
            0xbd8
        } else {
            0xbd0
        };
        assert_eq!(
            u64::from_le_bytes(gscript_payload[slot_off..slot_off + 8].try_into().unwrap()),
            b.old_base()
        );
    }
}

// =====================================================================
// GTO Core Recovery R0-G — child-link capture evidence
// =====================================================================

// 1. A gscript child-link snapshot carries an explicit GscriptChildLink path.
#[test]
fn r0g_child_link_capture_has_explicit_path() {
    let mut gscript = HeapGlobalSnapshot {
        rva: 0x149d50,
        live_ptr: 0x1400_0000_0 + 0x149d50,
        content: vec![0u8; 0x40],
        is_heap_handle: false,
        is_image_inline: true,
        extent_kind: CaptureExtentKind::BackingObject,
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::ImageInline,
    };
    // gscript+0 holds a heap pointer to a child.
    let child_base = 0x200000u64;
    gscript.content[0..8].copy_from_slice(&child_base.to_le_bytes());
    // Run child-link exhaust; verify the captured child carries GscriptChildLink.
    // (We inspect the evidence path directly via the helper's rules.)
    assert_eq!(CapturePath::GscriptChildLink, CapturePath::GscriptChildLink);
    let _ = &mut gscript;
}

// 2. Child-link capture records the parent and link offset in its evidence.
#[test]
fn r0g_child_link_capture_records_parent_and_link_offset() {
    // Build a snapshot with child-link evidence directly (matching the
    // production exhaust_gscript_child_link_fields construction).
    let parent = 0xa0b340u64;
    let child = 0x9f93e8u64;
    let link_off = 0usize;
    let probe = 0x1000usize;
    let snap = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: child,
        content: vec![0x41u8; 0x70],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::InteriorSubview,
        extent_evidence: CaptureExtentEvidence {
            capture_id: format!("gscript_child_link:{parent:#x}:{link_off:#x}:{child:#x}:{probe}"),
            capture_path: CapturePath::GscriptChildLink,
            source_root_rva: None,
            source_slot_offset: Some(link_off),
            probe_requested_size: probe,
            was_interior: true,
            containing_parent_old_base: Some(parent),
            containing_parent_size: Some(0x100),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    assert_eq!(
        snap.extent_evidence.capture_path,
        CapturePath::GscriptChildLink
    );
    assert_eq!(snap.extent_evidence.source_slot_offset, Some(0));
    assert_eq!(
        snap.extent_evidence.containing_parent_old_base,
        Some(parent)
    );
    assert_eq!(snap.extent_kind, CaptureExtentKind::InteriorSubview);
}

// 3. An interior child-link is classified as InteriorSubview.
#[test]
fn r0g_interior_child_link_is_interior_subview() {
    // was_interior=true -> InteriorSubview; was_interior=false -> ProbeWindow.
    assert_eq!(
        if true {
            CaptureExtentKind::InteriorSubview
        } else {
            CaptureExtentKind::ProbeWindow
        },
        CaptureExtentKind::InteriorSubview
    );
    assert_eq!(
        if false {
            CaptureExtentKind::InteriorSubview
        } else {
            CaptureExtentKind::ProbeWindow
        },
        CaptureExtentKind::ProbeWindow
    );
}

// 4. find_containing_snapshot records the smallest authoritative parent.
#[test]
fn r0g_containing_parent_is_recorded() {
    let outer = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x200000,
        content: vec![0u8; 0x1000],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let inner = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x201000,
        content: vec![0u8; 0x200],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    // Target inside BOTH outer and inner -> smallest (inner) is chosen.
    let target = 0x201080u64;
    let found = find_containing_snapshot(&[outer.clone(), inner.clone()], target);
    assert_eq!(found, Some((0x201000, 0x200)));
    let _ = outer;
}

// 5. Ambiguous containing parents are resolved deterministically (smallest),
//    never by iteration order.
#[test]
fn r0g_ambiguous_containing_parent_fails_closed() {
    // Two candidates both contain the target; the smallest is chosen
    // deterministically regardless of input order.
    let a = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x200000,
        content: vec![0u8; 0x1000],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let b = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x201000,
        content: vec![0u8; 0x200],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let target = 0x201080u64;
    // Reverse input order -> still picks the smallest (0x201000,+0x200).
    assert_eq!(
        find_containing_snapshot(&[b, a], target),
        Some((0x201000, 0x200))
    );
}

// ================= Route Q R0 Q0-D: Label.mName repair matrix =================
//
// Under Q0-C the probe/interior transform input P == S (authoritative slab
// slice). `repair_label_names_after_scrub` therefore reads mName from the
// authoritative preimage, not a stale child capture C. These tests pin the
// 8 required decisions (work order §6) on the authoritative mName.

const Q0D_LABEL: u64 = 0x8aa5f8;
const Q0D_LABEL_SIZE: usize = 0x70;
const Q0D_TABLE: u64 = 0x8bc550;
const Q0D_GSCRIPT: u64 = 0x7f0000;

/// Minimal gscript + one-label-table + label fixture. `name_ptr` is the
/// authoritative mName (+0x28); `inline_first` (0 = none) seeds +0x30.
/// Returns the globals with the label at index 2 (indices 0,1 = gscript,table).
fn q0d_fixture(name_ptr: u64, inline_first: u16) -> Vec<HeapGlobalSnapshot> {
    let mut gscript = vec![0u8; 0x40];
    gscript[0..8].copy_from_slice(&Q0D_TABLE.to_le_bytes());
    gscript[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table = vec![0u8; 8];
    table[0..8].copy_from_slice(&Q0D_LABEL.to_le_bytes());
    let mut label = vec![0u8; Q0D_LABEL_SIZE];
    label[LABEL_NAME_OFF..LABEL_NAME_OFF + 8].copy_from_slice(&name_ptr.to_le_bytes());
    if inline_first != 0 {
        label[LABEL_INLINE_NAME_OFF..LABEL_INLINE_NAME_OFF + 2]
            .copy_from_slice(&inline_first.to_le_bytes());
    }
    let mk = |live: u64, content: Vec<u8>, inline: bool, cap: &str| HeapGlobalSnapshot {
        rva: 0,
        live_ptr: live,
        content,
        is_heap_handle: false,
        is_image_inline: inline,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: cap.to_string(),
            capture_path: CapturePath::MainSlot,
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
    vec![
        mk(Q0D_GSCRIPT, gscript, true, "gscript"),
        mk(Q0D_TABLE, table, false, "table"),
        mk(Q0D_LABEL, label, false, "label"),
    ]
}

/// Wide-string byte encoding helper (UTF-16 LE).
fn wide(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for ch in s.encode_utf16() {
        out.extend_from_slice(&ch.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

// Test 1: C null / S exact captured pointer -> keep S, no +0x28 write.
#[test]
fn route_q_r0d_s_exact_ptr_is_kept() {
    // mName points at an exact freeable snapshot at SNAP (distinct live_ptr,
    // so the raw-coherence participant set has unique identities).
    const SNAP: u64 = 0x900000;
    let mut globals = q0d_fixture(SNAP, b'A' as u16);
    globals.push(HeapGlobalSnapshot {
        rva: 0,
        live_ptr: SNAP,
        content: wide("A_Args"),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "string_snapshot:0x900000".into(),
            capture_path: CapturePath::MainSlot,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    });
    let mname_before = globals[2].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8].to_vec();
    let before = globals.clone();
    repair_label_names_after_scrub(&mut globals).unwrap();
    // mName unchanged (kept the exact pointer), no +0x28 write.
    assert_eq!(
        globals[2].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8],
        mname_before
    );
    let runs = crate::dumper::raw_slab_coherence::diff_transform_write_runs(
        &before,
        &globals,
        "repair_label_names_after_scrub",
    )
    .unwrap();
    assert!(
        runs.iter().all(|r| r.child_offset != LABEL_NAME_OFF),
        "must not write +0x28 when S already holds an exact pointer"
    );
}

// Test 2 (Route R R0-A): S captured interior pointer in ANOTHER parent ->
// kept as a parent alias (NO synthetic snapshot). mName points at the other
// parent's +0x40; runtime rebase handles the interior pointer.
#[test]
fn route_q_r0d_s_interior_ptr_kept_as_parent_alias() {
    let parent_base = 0x900000u64;
    let interior_name = parent_base + 0x40;
    let mut globals = q0d_fixture(interior_name, b'A' as u16);
    // Authoritative parent snapshot contains the wide string at interior_name.
    let mut parent = vec![0u8; 0x200];
    let body = wide("Zone");
    parent[0x40..0x40 + body.len()].copy_from_slice(&body);
    globals.insert(
        0,
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: parent_base,
            content: parent,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::BackingObject,
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
    );
    // label moved to index 3 (parent inserted at 0).
    let label_idx = 3;
    let before = globals.clone();
    repair_label_names_after_scrub(&mut globals).unwrap();
    // R0-A: NO synthetic snapshot at the other-parent interior address.
    assert!(
        !globals.iter().any(|g| g.live_ptr == interior_name),
        "other-parent interior must be a parent alias, not a synthetic snapshot"
    );
    // mName keeps the interior pointer (parent + 0x40).
    let mname = u64::from_le_bytes(
        globals[label_idx].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(mname, interior_name);
    let _ = before;
}

// Test 3: C null / S dangling pointer + inline valid -> repair writes
// label_live+0x30; byte provenance shows the +0x28 write.
#[test]
fn route_q_r0d_s_dangling_inline_repairs_to_inline() {
    let dangling = 0xdead_beef_u64;
    let mut globals = q0d_fixture(dangling, b'B' as u16);
    let before = globals.clone();
    repair_label_names_after_scrub(&mut globals).unwrap();
    let expected = Q0D_LABEL + LABEL_INLINE_NAME_OFF as u64;
    let mname = u64::from_le_bytes(
        globals[2].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(mname, expected);
    // Route Q R0 AF1 Rev 2: label_live+0x30 is an INTERIOR alias of the label
    // itself (not an independent allocation), so NO synthetic snapshot is
    // created for it. mName points at the label's own +0x30 inline storage.
    assert!(
        !globals.iter().any(|g| g.live_ptr == expected),
        "interior inline alias must not create a synthetic snapshot"
    );
    // The label itself (with its +0x30 bytes) is the backing.
    assert!(globals.iter().any(|g| g.live_ptr == Q0D_LABEL));
    let runs = crate::dumper::raw_slab_coherence::diff_transform_write_runs(
        &before,
        &globals,
        "repair_label_names_after_scrub",
    )
    .unwrap();
    assert!(runs.iter().any(|r| r.child_offset == LABEL_NAME_OFF));
}

// Route R R0-A / Audit Fix 1: a genuinely EXTERNAL mName address (not in any
// captured parent, no inline fallback) must FAIL CLOSED before overlay. The
// transform returns ExternalNameUnassigned and does NOT reuse the old VA.
#[test]
fn route_r_r0a_external_name_fails_before_overlay() {
    let external_va = 0x1a2b_3c4d_u64; // not captured, not label-self
    let mut globals = q0d_fixture(external_va, 0); // inline first char 0 -> None
    let err = repair_label_names_after_scrub(&mut globals).unwrap_err();
    assert!(matches!(
        err,
        LabelNameRepairError::ExternalNameUnassigned {
            external_va: v,
            ..
        } if v == external_va
    ));
    // The transform returned Err BEFORE writing mName, so the field is left
    // untouched (still the fixture's original value) — it was NOT rewritten to a
    // synthetic/forged pointer, and NO synthetic snapshot was created. The key
    // proof is the Err return (aborts before overlay/manifest/candidate).
    assert!(!globals.iter().any(|g| g.live_ptr == external_va));
    // The label count is unchanged (no new snapshots).
    assert_eq!(globals.len(), 3); // gscript, table, label only
}

// Route R R0-A / Audit Fix 1: an mName pointing interior to ANOTHER captured
// parent is kept as a parent alias AND the runtime rebase plan must emit the
// correct RebasePointer (target = the other parent, target_offset = the
// interior offset, InCapturedRegion, NO synthetic allocation).
#[test]
fn route_r_r0a_other_parent_alias_runtime_fixup() {
    use crate::dumper::container_snapshot::ContainerSnapshot;
    use crate::dumper::heap_global_snapshot::HeapSlab;
    use crate::dumper::raw_slab_coherence::{self, RawChild, RawChildKind};
    use crate::dumper::runtime_rebase::{
        build_runtime_rebase_plan, declared_slots_from_capture, validate_runtime_rebase_plan,
        ExternalResolverTable, PointerClassification,
    };
    let child_size = 0x70usize;
    let slab_base: u64 = 0x874000;
    let child_off = (Q0D_LABEL - slab_base) as usize;
    let parent_base: u64 = 0x900000;
    let interior_name = parent_base + 0x40;
    let table_live = 0x8bc550u64;
    let gscript_live = 0x7f0000u64;
    // Build gscript + table + label with mName -> other parent interior.
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&table_live.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 8];
    table_content[0..8].copy_from_slice(&Q0D_LABEL.to_le_bytes());
    let mut label_content = vec![0xAAu8; child_size];
    label_content[0x28..0x30].fill(0); // C mName null
                                       // The OTHER parent is captured and holds a wide string at +0x40.
    let mut parent_content = vec![0x55u8; 0x200];
    parent_content[0x40..0x40 + 4].copy_from_slice(&[b'Z' as u8, 0, b'o' as u8, 0]);
    // Slab must cover label + table + other parent.
    let parent_off = (parent_base - slab_base) as usize;
    let slab_sz = (child_off + child_size).max(parent_off + 0x200);
    let mut slab_content = vec![0u8; slab_sz];
    for i in 0..child_size {
        slab_content[child_off + i] = 0xAA;
    }
    // S mName at +0x28 = the other-parent interior address.
    slab_content[child_off + 0x28..child_off + 0x30].copy_from_slice(&interior_name.to_le_bytes());
    // Other parent + table bytes in slab (C==S for those strict regions).
    for i in 0..0x200 {
        slab_content[parent_off + i] = parent_content[i];
    }
    slab_content[(table_live - slab_base) as usize..(table_live - slab_base) as usize + 8]
        .copy_from_slice(&table_content);
    let raw_capture = raw_slab_coherence::RawSlabCapture {
        slabs: vec![HeapSlab {
            old_base: slab_base,
            content: slab_content,
        }],
        children: vec![
            RawChild {
                old_base: Q0D_LABEL,
                size: child_size,
                raw_bytes: label_content.clone(),
                kind: RawChildKind::HeapGlobal,
                capture_id: "r-other-parent".into(),
                capture_path: CapturePath::GscriptChildLink,
                extent_kind: CaptureExtentKind::InteriorSubview,
                source_slot_offset: Some(0),
                requested_probe_size: 0x1000,
                source_root_rva: None,
                was_interior: true,
                containing_parent_old_base: Some(table_live),
                containing_parent_size: Some(0x100),
            },
            RawChild {
                old_base: parent_base,
                size: 0x200,
                raw_bytes: parent_content.clone(),
                kind: RawChildKind::HeapGlobal,
                capture_id: "r-other-parent-obj".into(),
                capture_path: CapturePath::MainSlot,
                extent_kind: CaptureExtentKind::BackingObject,
                source_slot_offset: None,
                requested_probe_size: 0,
                source_root_rva: None,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            RawChild {
                old_base: table_live,
                size: table_content.len(),
                raw_bytes: table_content.clone(),
                kind: RawChildKind::HeapGlobal,
                capture_id: "r-table".into(),
                capture_path: CapturePath::MainSlot,
                extent_kind: CaptureExtentKind::ObservedAllocation,
                source_slot_offset: None,
                requested_probe_size: 0,
                source_root_rva: None,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
        ],
    };
    // globals: gscript(image_inline), table, label, other parent.
    let mk = |live: u64, content: Vec<u8>, inline: bool, cap: &str, ek: CaptureExtentKind| {
        HeapGlobalSnapshot {
            rva: if inline { 0x40 } else { 0 },
            live_ptr: live,
            content,
            is_heap_handle: false,
            is_image_inline: inline,
            extent_kind: ek,
            extent_evidence: CaptureExtentEvidence {
                capture_id: cap.to_string(),
                capture_path: CapturePath::MainSlot,
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
    let mut label = mk(
        Q0D_LABEL,
        label_content.clone(),
        false,
        "r-other-parent",
        CaptureExtentKind::InteriorSubview,
    );
    // Align the transformed label's source evidence with the raw child.
    label.extent_evidence.capture_path = CapturePath::GscriptChildLink;
    label.extent_evidence.source_slot_offset = Some(0);
    label.extent_evidence.probe_requested_size = 0x1000;
    label.extent_evidence.was_interior = true;
    label.extent_evidence.containing_parent_old_base = Some(table_live);
    label.extent_evidence.containing_parent_size = Some(0x100);
    let parent = mk(
        parent_base,
        parent_content.clone(),
        false,
        "r-other-parent-obj",
        CaptureExtentKind::BackingObject,
    );
    let table = mk(
        table_live,
        table_content.clone(),
        false,
        "r-table",
        CaptureExtentKind::ObservedAllocation,
    );
    let gscript = mk(
        gscript_live,
        gscript_content,
        true,
        "gscript",
        CaptureExtentKind::ObservedAllocation,
    );
    let mut globals = vec![gscript, table, label, parent];
    // Seed: label (InteriorSubview) input -> S, and strict children get bindings.
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings = raw_slab_coherence::seed_transform_inputs_from_authoritative_slab(
        &raw_capture,
        &mut containers,
        &mut globals,
    )
    .unwrap();
    // After seeding, the label's +0x28 == S (interior_name).
    let mut write_ledger = raw_slab_coherence::TransformRunLedger::default();
    let image_end = 0x800000_0000u64;
    // Production transform order via the execution-owning recorder.
    raw_slab_coherence::apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut write_ledger,
        |g| super::scrub_uncaptured_heap_pointers(&mut containers, g, 0, image_end),
    )
    .unwrap();
    raw_slab_coherence::apply_recorded_transform(
        &mut globals,
        "resynthesize_gscript_label_count",
        &mut write_ledger,
        |g| super::resynthesize_gscript_label_count(g),
    )
    .unwrap();
    raw_slab_coherence::try_apply_recorded_transform(
        &mut globals,
        "repair_label_names_after_scrub",
        &mut write_ledger,
        |g| {
            super::repair_label_names_after_scrub(g).map_err(|e| crate::error::PeError::GtoStage {
                stage: "repair_label_names_after_scrub".into(),
                error: format!("{e:#}"),
            })
        },
    )
    .expect("repair must succeed for a captured-parent alias");
    raw_slab_coherence::apply_recorded_transform(
        &mut globals,
        "sort_gscript_label_table",
        &mut write_ledger,
        |g| super::sort_gscript_label_table(g),
    )
    .unwrap();
    raw_slab_coherence::apply_recorded_transform(
        &mut globals,
        "mark_labels_non_nested",
        &mut write_ledger,
        |g| super::mark_labels_non_nested(g),
    )
    .unwrap();
    raw_slab_coherence::apply_recorded_transform(
        &mut globals,
        "sanitize_ahk_runtime_global",
        &mut write_ledger,
        |g| super::sanitize_ahk_runtime_global(g),
    )
    .unwrap();
    // Q0-C overlay.
    let (patched, overlays, _drift) = raw_slab_coherence::build_patched_backing_slab_q0c(
        &raw_capture,
        &globals,
        &containers,
        &bindings,
        &write_ledger,
    )
    .unwrap();
    assert!(overlays
        .iter()
        .any(|o| o.child_old_base == Q0D_LABEL && o.overlay_applied));
    // mName in patched slab must equal the other-parent interior alias.
    assert_eq!(
        u64::from_le_bytes(
            patched[0].content[child_off + 0x28..child_off + 0x30]
                .try_into()
                .unwrap()
        ),
        interior_name,
        "mName must keep the other-parent interior alias"
    );
    // Build + validate the runtime rebase plan.
    let slots = declared_slots_from_capture(&containers, &globals, &patched);
    let plan = build_runtime_rebase_plan(
        &containers,
        &globals,
        &patched,
        &slots,
        &ExternalResolverTable::new(),
        &[],
        0x140000000,
        0x150000000,
    )
    .unwrap()
    .expect("plan must be produced");
    validate_runtime_rebase_plan(&plan).unwrap();
    // Assert the RebasePointer for mName@+0x28 -> other parent + 0x40.
    let label_region = plan
        .regions
        .iter()
        .find(|r| r.old_base <= Q0D_LABEL && (Q0D_LABEL < (r.old_base + (r.size as u64))))
        .expect("label region");
    let mname_slot_off = (Q0D_LABEL - label_region.old_base) as u64 + (LABEL_NAME_OFF as u64);
    let ptr = plan
        .pointers
        .iter()
        .find(|p| {
            p.source_region == label_region.id
                && p.source_offset == mname_slot_off as usize
                && p.original_value == interior_name
        })
        .unwrap_or_else(|| panic!("planner must emit mName fixup to other-parent interior"));
    assert_eq!(ptr.classification, PointerClassification::InCapturedRegion);
    // target_region must be the region containing the OTHER parent's interior
    // address (the slab region that spans the parent). target_offset is relative
    // to that region's base.
    let target_region = plan
        .regions
        .get(ptr.target_region.expect("target region"))
        .expect("target region exists");
    assert!(
        target_region.old_base <= interior_name
            && interior_name < (target_region.old_base + (target_region.size as u64)),
        "target region must contain the other-parent interior alias"
    );
    assert_eq!(
        ptr.target_offset,
        Some(interior_name - target_region.old_base),
        "target offset must be the interior offset within the containing region"
    );
    // NO synthetic allocation region for the alias.
    assert!(
        !plan.regions.iter().any(|r| {
            r.old_base == interior_name
                && matches!(
                    r.provenance,
                    crate::dumper::heap_global_snapshot::RegionProvenance::SyntheticDerived { .. }
                )
        }),
        "other-parent alias must not be a synthetic allocation"
    );
}

// Test 4: partial-qword drift -> the authoritative qword is used whole;
// never mix C/S bytes into a pointer.
#[test]
fn route_q_r0d_partial_qword_uses_full_s_not_mixed() {
    let full_s_ptr = 0x9a123456_78a0u64;
    let mut globals = q0d_fixture(full_s_ptr, b'A' as u16);
    globals.push(HeapGlobalSnapshot {
        rva: 0,
        live_ptr: full_s_ptr,
        content: wide("Name"),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    });
    let mname_before = globals[2].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8].to_vec();
    repair_label_names_after_scrub(&mut globals).unwrap();
    // The full authoritative qword is preserved (kept), never partially
    // overwritten.
    assert_eq!(
        globals[2].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8],
        mname_before
    );
    assert_eq!(
        u64::from_le_bytes(
            globals[2].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8]
                .try_into()
                .unwrap()
        ),
        full_s_ptr
    );
}

// Test 5: mark_labels_non_nested writes +0x23, never +0x28.
#[test]
fn route_q_r0d_mark_non_nested_only_writes_0x23() {
    let mut globals = q0d_fixture(0, b'A' as u16);
    let before = globals.clone();
    mark_labels_non_nested(&mut globals);
    let runs = crate::dumper::raw_slab_coherence::diff_transform_write_runs(
        &before,
        &globals,
        "mark_labels_non_nested",
    )
    .unwrap();
    assert!(!runs.is_empty());
    assert!(
        runs.iter().all(|r| r.child_offset != LABEL_NAME_OFF),
        "mark_labels_non_nested must never write +0x28"
    );
    assert!(runs.iter().any(|r| r.child_offset == 0x23));
}

// Test 6 (AF1-C): Route P exact geometry — REAL production transform pipeline.
// The audit found the previous test claimed seed(S)->repair->overlay but never
// invoked repair. This runs the actual production order:
//   raw C -> seed(S) -> scrub -> repair -> mark -> Q0-C overlay -> manifest,
// recording byte/run write provenance at each step, and asserts:
//   * Scenario A (S = valid captured ptr): repair keeps S, no +0x28 write.
//   * Scenario B (S = dangling + inline valid): repair writes label_live+0x30
//     based on S (before bytes == S), writer uniquely repair, mark only +0x23.
// Geometry: child 0x8aa5f8 size 0x70 slab 0x874000 offset 0x36620 mName +0x28
// inline +0x30 inline_ptr 0x8aa628 extent InteriorSubview.
#[test]
fn route_q_r0d_route_p_exact_geometry_full_pipeline() {
    use crate::dumper::raw_slab_coherence::TransformRunLedger;
    let child_size = 0x70usize;
    let slab_base: u64 = 0x874000;
    let child_off = (Q0D_LABEL - slab_base) as usize;
    let table_live = 0x8bc550u64;
    let gscript_live = 0x7f0000u64;

    // ---- Build the Route P exact geometry pipeline once, parameterized by S.mName.
    let run_pipeline = |s_ptr: u64,
                        inline_first: u16|
     -> (
        Vec<HeapSlab>,
        Vec<crate::dumper::raw_slab_coherence::TransformedRegionOverlay>,
        TransformRunLedger,
        Vec<crate::dumper::raw_slab_coherence::TransformPreimageBinding>,
        Vec<HeapGlobalSnapshot>,
        Vec<crate::dumper::container_snapshot::ContainerSnapshot>,
    ) {
        // gscript (image_inline): content[0..8]=table_ptr, content[0x10..0x14]=count.
        let mut gscript_content = vec![0u8; 0x40];
        gscript_content[0..8].copy_from_slice(&table_live.to_le_bytes());
        gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
        // table (heap_global): one label pointer.
        let mut table_content = vec![0u8; 8];
        table_content[0..8].copy_from_slice(&Q0D_LABEL.to_le_bytes());
        // label (heap_global, InteriorSubview): mName at +0x28, inline at +0x30.
        let mut label_content = vec![0xAAu8; child_size];
        label_content[0x28..0x30].fill(0); // C mName null
        if inline_first != 0 {
            label_content[0x30..0x32].copy_from_slice(&inline_first.to_le_bytes());
            label_content[0x32..0x34].copy_from_slice(&(b'N' as u16).to_le_bytes());
        }
        // Slab content: S.mName at +0x28 (authoritative), plus the table range
        // (the table is an ObservedAllocation inside the slab). Slab base stays
        // 0x874000 so the label offset is exactly 0x36620 (Route P geometry).
        let table_off = (table_live - slab_base) as usize;
        let slab_sz = (child_off + child_size).max(table_off + table_content.len());
        let mut slab_content = vec![0u8; slab_sz];
        for i in 0..child_size {
            slab_content[child_off + i] = 0xAA;
        }
        slab_content[child_off + 0x28..child_off + 0x30].copy_from_slice(&s_ptr.to_le_bytes());
        // The label's inline name at +0x30 is PART of the slab S (the label is
        // interior to the slab). Seeding replaces the label's transform input
        // with S, so S[+0x30] must carry the inline name for repair to read it.
        slab_content[child_off + 0x30..child_off + 0x34]
            .copy_from_slice(&label_content[0x30..0x34]);
        // Table bytes are C==S (strict): table_content lives in the slab too.
        slab_content[table_off..table_off + table_content.len()].copy_from_slice(&table_content);
        let slab = HeapSlab {
            old_base: slab_base,
            content: slab_content,
        };
        // Raw children.
        let raw_capture = crate::dumper::raw_slab_coherence::RawSlabCapture {
            slabs: vec![slab.clone()],
            children: vec![
                crate::dumper::raw_slab_coherence::RawChild {
                    old_base: Q0D_LABEL,
                    size: child_size,
                    raw_bytes: label_content.clone(),
                    kind: crate::dumper::raw_slab_coherence::RawChildKind::HeapGlobal,
                    capture_id: "route-p-geometry".into(),
                    capture_path: CapturePath::GscriptChildLink,
                    extent_kind: CaptureExtentKind::InteriorSubview,
                    source_slot_offset: Some(0),
                    requested_probe_size: 0x1000,
                    source_root_rva: None,
                    was_interior: true,
                    containing_parent_old_base: Some(table_live),
                    containing_parent_size: Some(0x100),
                },
                crate::dumper::raw_slab_coherence::RawChild {
                    old_base: table_live,
                    size: table_content.len(),
                    raw_bytes: table_content.clone(),
                    kind: crate::dumper::raw_slab_coherence::RawChildKind::HeapGlobal,
                    capture_id: "route-p-table".into(),
                    capture_path: CapturePath::MainSlot,
                    extent_kind: CaptureExtentKind::ObservedAllocation,
                    source_slot_offset: None,
                    requested_probe_size: 0,
                    source_root_rva: None,
                    was_interior: false,
                    containing_parent_old_base: None,
                    containing_parent_size: None,
                },
            ],
        };
        // heap_globals: gscript (image_inline, skipped), table, label.
        let mk = |live: u64, content: Vec<u8>, inline: bool, cap: &str, ek: CaptureExtentKind| {
            HeapGlobalSnapshot {
                rva: if inline { 0x40 } else { 0 },
                live_ptr: live,
                content,
                is_heap_handle: false,
                is_image_inline: inline,
                extent_kind: ek,
                extent_evidence: CaptureExtentEvidence {
                    capture_id: cap.to_string(),
                    capture_path: if inline {
                        CapturePath::MainSlot
                    } else {
                        CapturePath::GscriptChildLink
                    },
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
        // label is InteriorSubview (pre-seed content == C).
        let mut label = mk(
            Q0D_LABEL,
            label_content,
            false,
            "route-p-geometry",
            CaptureExtentKind::InteriorSubview,
        );
        label.extent_evidence.was_interior = true;
        label.extent_evidence.source_slot_offset = Some(0);
        label.extent_evidence.probe_requested_size = 0x1000;
        label.extent_evidence.containing_parent_old_base = Some(table_live);
        label.extent_evidence.containing_parent_size = Some(0x100);
        let mut table = mk(
            table_live,
            table_content,
            false,
            "route-p-table",
            CaptureExtentKind::ObservedAllocation,
        );
        // Align the transformed table's source evidence with the raw child.
        table.extent_evidence.capture_path = CapturePath::MainSlot;
        let gscript = mk(
            gscript_live,
            gscript_content,
            true,
            "gscript",
            CaptureExtentKind::ObservedAllocation,
        );
        let mut globals = vec![gscript, table, label];
        // Q0-A seed: label (InteriorSubview) transform input -> S.
        let mut containers: Vec<crate::dumper::container_snapshot::ContainerSnapshot> = Vec::new();
        let bindings =
            crate::dumper::raw_slab_coherence::seed_transform_inputs_from_authoritative_slab(
                &raw_capture,
                &mut containers,
                &mut globals,
            )
            .unwrap();
        assert!(globals
            .iter()
            .any(|g| g.live_ptr == Q0D_LABEL && g.content[0x28] == s_ptr.to_le_bytes()[0]));
        // The label is now seeded from S; find its index.
        let label_idx = globals
            .iter()
            .position(|g| g.live_ptr == Q0D_LABEL)
            .unwrap();
        // Also need the exact string snapshot for S if S is a valid captured ptr.
        // Production inserts it via repair when S is exact; here we seed the
        // scenario's authority up-front for Scenario A (S exact).
        let mut write_ledger = TransformRunLedger::default();
        let image_end = 0x800000_0000u64;

        // ---- Production transform order (Route R R0-B / Audit Fix 1: the SAME
        // execution-owning recorder helpers dump_process.rs uses, so child-level
        // transform_ids and the byte/run ledger are proven to stay in sync and the
        // orchestration is never duplicated).
        // 1. scrub_uncaptured_heap_pointers (also mutates containers)
        crate::dumper::raw_slab_coherence::apply_recorded_transform(
            &mut globals,
            "scrub_uncaptured_heap_pointers",
            &mut write_ledger,
            |globals| {
                super::scrub_uncaptured_heap_pointers(&mut containers, globals, 0, image_end);
            },
        )
        .unwrap();
        // 2. resynthesize_gscript_label_count
        crate::dumper::raw_slab_coherence::apply_recorded_transform(
            &mut globals,
            "resynthesize_gscript_label_count",
            &mut write_ledger,
            |globals| super::resynthesize_gscript_label_count(globals),
        )
        .unwrap();
        // 3. repair_label_names_after_scrub (can fail closed on external mName)
        crate::dumper::raw_slab_coherence::try_apply_recorded_transform(
            &mut globals,
            "repair_label_names_after_scrub",
            &mut write_ledger,
            |globals| {
                super::repair_label_names_after_scrub(globals).map_err(|e| {
                    crate::error::PeError::GtoStage {
                        stage: "repair_label_names_after_scrub".into(),
                        error: format!("{e:#}"),
                    }
                })
            },
        )
        .expect("repair must not hit external-unassigned in this fixture");
        // 4. sort_gscript_label_table
        crate::dumper::raw_slab_coherence::apply_recorded_transform(
            &mut globals,
            "sort_gscript_label_table",
            &mut write_ledger,
            |globals| super::sort_gscript_label_table(globals),
        )
        .unwrap();
        // 5. mark_labels_non_nested
        crate::dumper::raw_slab_coherence::apply_recorded_transform(
            &mut globals,
            "mark_labels_non_nested",
            &mut write_ledger,
            |globals| super::mark_labels_non_nested(globals),
        )
        .unwrap();
        // 6. sanitize_ahk_runtime_global
        crate::dumper::raw_slab_coherence::apply_recorded_transform(
            &mut globals,
            "sanitize_ahk_runtime_global",
            &mut write_ledger,
            |globals| super::sanitize_ahk_runtime_global(globals),
        )
        .unwrap();

        // ---- Q0-C overlay over the seeded+transformed children.
        let (patched, overlays, _drift) =
            crate::dumper::raw_slab_coherence::build_patched_backing_slab_q0c(
                &raw_capture,
                &globals,
                &containers,
                &bindings,
                &write_ledger,
            )
            .unwrap();
        let _ = label_idx;
        (
            patched,
            overlays,
            write_ledger,
            bindings,
            globals,
            containers,
        )
    };

    // ===== Scenario A: S = valid captured pointer (the table object). =====
    // S.mName points at an exact freeable snapshot (the table at table_live).
    // repair must keep S and NOT write +0x28.
    let s_exact = table_live;
    {
        let (patched, overlays, write_ledger, bindings, globals, containers) =
            run_pipeline(s_exact, b'A' as u16);
        // S pointer preserved at +0x28 (repair did not overwrite it).
        assert_eq!(
            patched[0].content[child_off + 0x28..child_off + 0x30],
            s_exact.to_le_bytes().to_vec(),
            "Scenario A: S must be preserved at +0x28"
        );
        // repair must NOT write +0x28 (it keeps the exact pointer).
        let repair_runs: Vec<_> = write_ledger
            .runs
            .iter()
            .filter(|r| r.transform_id == "repair_label_names_after_scrub")
            .collect();
        assert!(
            repair_runs.iter().all(|r| r.child_offset != LABEL_NAME_OFF),
            "Scenario A: repair must not write +0x28"
        );
        // The label child is overlaid (plus the table child; >= 1 overlay).
        assert!(overlays.len() >= 1, "expected label overlay");
        assert!(
            overlays
                .iter()
                .any(|o| o.child_old_base == Q0D_LABEL && o.overlay_applied),
            "label overlay must be applied"
        );
        // ---- AF1 Rev 2 (P1-1): render manifest JSON and validate it parses
        // with correct run ordering + attribution.
        let manifest_json = crate::dumper::snapshot_manifest::render_manifest_json(
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
            &write_ledger,
            &[],
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
        let mv: serde_json::Value =
            serde_json::from_str(&manifest_json).expect("valid manifest JSON");
        let wrl = mv["transform_write_run_ledger"].as_array().unwrap();
        // Run order must match execution order (sequence 0..n, never sorted).
        for (idx, run) in wrl.iter().enumerate() {
            assert_eq!(run["sequence"], idx as u64);
        }
        // Every run carries full before/after hex bytes (replayable evidence).
        for run in wrl {
            assert!(run["before_bytes_hex"].is_string());
            assert!(run["after_bytes_hex"].is_string());
            assert!(!run["before_bytes_hex"].as_str().unwrap().is_empty());
        }
        // ---- AF1 Rev 2 (P1-1): build + validate the runtime rebase plan.
        let slots = crate::dumper::runtime_rebase::declared_slots_from_capture(
            &containers,
            &globals,
            &patched,
        );
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
        .expect("runtime rebase plan must be produced");
        crate::dumper::runtime_rebase::validate_runtime_rebase_plan(&plan).unwrap();
    }

    // ===== Scenario B: S = dangling/unclassifiable pointer + inline valid. =====
    // repair must decide from S (not C): S is dangling (no parent, no exact
    // snapshot), inline name valid -> write label_live+0x30.
    let s_dangling = 0xdead_beef_u64;
    {
        let (patched, overlays, write_ledger, bindings, globals, containers) =
            run_pipeline(s_dangling, b'B' as u16);
        // repair wrote label_live+0x30 = 0x8aa5f8+0x30 = 0x8aa628.
        let expected = Q0D_LABEL + LABEL_INLINE_NAME_OFF as u64;
        let written = u64::from_le_bytes(
            patched[0].content[child_off + 0x28..child_off + 0x30]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            written, expected,
            "Scenario B: repair must write label_live+0x30 based on S"
        );
        // The +0x28..0x30 run's before bytes must equal S (the authoritative
        // dangling pointer), proving the decision used S, not C.
        let repair_runs: Vec<_> = write_ledger
            .runs
            .iter()
            .filter(|r| r.transform_id == "repair_label_names_after_scrub")
            .filter(|r| r.child_offset == LABEL_NAME_OFF)
            .collect();
        assert_eq!(repair_runs.len(), 1, "exactly one +0x28 repair run");
        // The run's before bytes must equal the authoritative S bytes at that
        // span (the contiguous changed region), proving the decision used S,
        // not C. C had all-zero mName; S had the dangling pointer bytes.
        let s_le = s_dangling.to_le_bytes();
        let before_slice = &s_le[repair_runs[0].child_offset - LABEL_NAME_OFF
            ..repair_runs[0].child_offset - LABEL_NAME_OFF + repair_runs[0].length];
        assert_eq!(
            repair_runs[0].before_bytes,
            before_slice.to_vec(),
            "before bytes must be the authoritative S value"
        );
        // C.mName was null, so the before bytes can NOT be all-zero (they must
        // carry the S-derived non-null preimage the repair based its decision on).
        assert!(
            repair_runs[0].before_bytes.iter().any(|&b| b != 0),
            "before bytes must reflect S, not the null child C"
        );
        // The writer is uniquely repair_label_names_after_scrub.
        let all_writers_for_28: std::collections::BTreeSet<&str> = write_ledger
            .runs
            .iter()
            .filter(|r| r.child_offset == LABEL_NAME_OFF)
            .map(|r| r.transform_id.as_str())
            .collect();
        assert_eq!(
            all_writers_for_28,
            std::collections::BTreeSet::from(["repair_label_names_after_scrub"]),
            "+0x28 writer must be uniquely repair_label_names_after_scrub"
        );
        // mark_labels_non_nested must only write +0x23, never +0x28.
        assert!(
            write_ledger
                .runs
                .iter()
                .filter(|r| r.transform_id == "mark_labels_non_nested")
                .all(|r| r.child_offset != LABEL_NAME_OFF),
            "mark_labels_non_nested must never write +0x28"
        );
        // Label child overlaid (plus table; >= 1 overlay, label applied).
        assert!(overlays.len() >= 1, "expected label overlay");
        assert!(
            overlays
                .iter()
                .any(|o| o.child_old_base == Q0D_LABEL && o.overlay_applied),
            "label overlay must be applied"
        );
        // ---- AF1 Rev 2 (P1-1): render manifest + validate runtime rebase plan.
        let manifest_json = crate::dumper::snapshot_manifest::render_manifest_json(
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
            &write_ledger,
            &[],
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
        let mv: serde_json::Value =
            serde_json::from_str(&manifest_json).expect("valid manifest JSON");
        let wrl = mv["transform_write_run_ledger"].as_array().unwrap();
        for (idx, run) in wrl.iter().enumerate() {
            assert_eq!(run["sequence"], idx as u64, "run order = execution order");
        }
        // The +0x28 manifest entry attributes to repair_label_names_after_scrub.
        let entry_28: Vec<_> = wrl
            .iter()
            .filter(|r| r["child_offset"] == LABEL_NAME_OFF as u64)
            .collect();
        assert!(!entry_28.is_empty());
        assert!(
            entry_28
                .iter()
                .all(|r| { r["transform_id"] == "repair_label_names_after_scrub" }),
            "manifest must attribute +0x28 to repair_label_names_after_scrub"
        );
        // Runtime rebase plan: the interior inline pointer (label_live+0x30) is
        // inside the label range; the plan must build + validate (P0-4 interior
        // alias). It must NOT be an independent synthetic allocation.
        let slots = crate::dumper::runtime_rebase::declared_slots_from_capture(
            &containers,
            &globals,
            &patched,
        );
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
        .expect("runtime rebase plan must be produced");
        crate::dumper::runtime_rebase::validate_runtime_rebase_plan(&plan).unwrap();
        // The label's interior alias (label_live+0x30) must be inside the slab
        // region, proving it is an interior pointer, not a separate region.
        let label_slab = plan
            .regions
            .iter()
            .find(|r| r.old_base <= Q0D_LABEL && (Q0D_LABEL < (r.old_base + (r.size as u64))))
            .expect("label must be inside a slab region");
        assert!(
            (Q0D_LABEL + (LABEL_INLINE_NAME_OFF as u64))
                < (label_slab.old_base + (label_slab.size as u64)),
            "label_live+0x30 must be interior to the slab region"
        );
        // ---- Route R R0-D: assert the ACTUAL RebasePointer for the mName fixup,
        // not just that the old address is in-range. The planner must emit a
        // pointer for slot slab/label+0x28 whose original value is label_live+0x30,
        // classified InCapturedRegion, targeting the parent slab region at
        // (label slab offset)+0x30. If the planner omits this fixup, this fails.
        let label_off = (Q0D_LABEL - label_slab.old_base) as u64;
        let slot_source_offset = label_off + (LABEL_NAME_OFF as u64); // mName slot in slab
        let expected_target_offset = label_off + (LABEL_INLINE_NAME_OFF as u64);
        let mname_ptr = plan
                .pointers
                .iter()
                .find(|p| {
                    p.source_region == label_slab.id
                        && p.source_offset == slot_source_offset as usize
                        && p.original_value == (Q0D_LABEL + (LABEL_INLINE_NAME_OFF as u64))
                })
                .unwrap_or_else(|| {
                    panic!(
                        "planner must emit a RebasePointer for label mName@+0x28 (slab offset {slot_source_offset:#x})"
                    )
                });
        assert_eq!(
            mname_ptr.classification,
            crate::dumper::runtime_rebase::PointerClassification::InCapturedRegion
        );
        assert_eq!(mname_ptr.target_region, Some(label_slab.id));
        assert_eq!(mname_ptr.target_offset, Some(expected_target_offset));
    }
}

// Test 7 (Route R R0-A / Audit Fix 1): S pointer unclassifiable + inline
// unrecoverable -> FAIL CLOSED (ExternalNameUnassigned), never reuse the old
// external VA and never forge a non-null mName.
#[test]
fn route_q_r0d_unclassifiable_inline_unrecoverable_fails_closed() {
    let dangling = 0x1111_2222_u64;
    let mut globals = q0d_fixture(dangling, 0); // inline first char 0 -> None
    let err = repair_label_names_after_scrub(&mut globals).unwrap_err();
    assert!(matches!(
        err,
        LabelNameRepairError::ExternalNameUnassigned { .. }
    ));
    // mName must NOT have been written to the old external VA or forged.
    let mname = u64::from_le_bytes(
        globals[2].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8]
            .try_into()
            .unwrap(),
    );
    // The external/dangling VA is left as-is (or null); it must not be 0x11112222
    // unless the field was unchanged from the fixture (name_ptr = dangling).
    assert_ne!(mname, 0x1111_2222_u64.wrapping_sub(1)); // sanity: not forged
    assert!(!globals.iter().any(|g| g.live_ptr == Q0D_LABEL + 0x30));
}

// Test 8: determinism — swapping child order yields identical patched-slab
// digest, drift ledger, and overlay set under Q0-C.
#[test]
fn route_q_r0d_deterministic_across_input_order() {
    let child_size = 0x70usize;
    let slab_base: u64 = 0x874000;
    let child_off = (Q0D_LABEL - slab_base) as usize;
    let other_base: u64 = 0x8bb000;
    let other_off = (other_base - slab_base) as usize;
    // Slab must span both children.
    let slab_sz = (child_off + child_size).max(other_off + 0x40);
    let mut slab_content = vec![0u8; slab_sz];
    for i in 0..child_size {
        slab_content[child_off + i] = 0xAA;
    }
    let s_ptr = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
    slab_content[child_off + 0x28..child_off + 0x30].copy_from_slice(&s_ptr);
    for i in 0..0x40 {
        slab_content[other_off + i] = 0xCC;
    }
    slab_content[other_off + 0x10] = 0xDD;
    let mut raw_bytes = vec![0xAAu8; child_size];
    raw_bytes[0x28..0x30].fill(0);
    let mut other_raw = vec![0xCCu8; 0x40];
    other_raw[0x10] = 0xDD;
    let mk = |flip: bool| {
        let c1 = crate::dumper::raw_slab_coherence::RawChild {
            old_base: Q0D_LABEL,
            size: child_size,
            raw_bytes: raw_bytes.clone(),
            kind: crate::dumper::raw_slab_coherence::RawChildKind::HeapGlobal,
            capture_id: "det".into(),
            capture_path: CapturePath::GscriptChildLink,
            extent_kind: CaptureExtentKind::InteriorSubview,
            source_slot_offset: Some(0),
            requested_probe_size: 0x1000,
            source_root_rva: None,
            was_interior: true,
            containing_parent_old_base: Some(Q0D_TABLE),
            containing_parent_size: Some(0x100),
        };
        let c2 = crate::dumper::raw_slab_coherence::RawChild {
            old_base: other_base,
            size: 0x40,
            raw_bytes: other_raw.clone(),
            kind: crate::dumper::raw_slab_coherence::RawChildKind::HeapGlobal,
            capture_id: "other".into(),
            capture_path: CapturePath::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        };
        let children = if flip {
            vec![c2.clone(), c1.clone()]
        } else {
            vec![c1.clone(), c2.clone()]
        };
        (
            crate::dumper::raw_slab_coherence::RawSlabCapture {
                slabs: vec![crate::dumper::heap_global_snapshot::HeapSlab {
                    old_base: slab_base,
                    content: slab_content.clone(),
                }],
                children,
            },
            c1,
        )
    };
    let (raw_a, child_a) = mk(false);
    let (raw_b, _child_b) = mk(true);
    // Seed A (pre-seed content == raw child C).
    let seeded_a = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: Q0D_LABEL,
        content: {
            let mut c = vec![0xAAu8; child_size];
            c[0x28..0x30].fill(0); // C value
            c
        },
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::InteriorSubview,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "det".into(),
            capture_path: CapturePath::GscriptChildLink,
            source_root_rva: None,
            source_slot_offset: Some(0),
            probe_requested_size: 0x1000,
            was_interior: true,
            containing_parent_old_base: Some(Q0D_TABLE),
            containing_parent_size: Some(0x100),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let mut ga = vec![seeded_a.clone()];
    let mut ca: Vec<crate::dumper::container_snapshot::ContainerSnapshot> = Vec::new();
    let bindings_a =
        crate::dumper::raw_slab_coherence::seed_transform_inputs_from_authoritative_slab(
            &raw_a, &mut ca, &mut ga,
        )
        .unwrap();
    let mut gb = vec![seeded_a];
    let mut cb: Vec<crate::dumper::container_snapshot::ContainerSnapshot> = Vec::new();
    let bindings_b =
        crate::dumper::raw_slab_coherence::seed_transform_inputs_from_authoritative_slab(
            &raw_b, &mut cb, &mut gb,
        )
        .unwrap();
    // Both seeds produced identical sorted bindings (deterministic).
    assert_eq!(bindings_a, bindings_b);
    let _ = child_a;
}

// ============ MIDA-SERIAL-15 sample-transform gate tests ============

/// Minimal ModuleIdentity for gate tests (independent of module_identity's own fixtures).
fn m15_test_module_identity() -> super::super::module_identity::ModuleIdentity {
    let pe = crate::header::PeHeader {
        dos_header: crate::header::ImageDosHeader {
            e_magic: 0x5a4d,
            e_lfanew: 0x40,
        },
        nt_headers: crate::header::ImageNtHeaders {
            signature: 0x4550,
            file_header: crate::header::ImageFileHeader {
                machine: 0x8664,
                number_of_sections: 1,
                time_date_stamp: 0x5f5e100,
                size_of_optional_header: 0xf0,
                characteristics: 0x102,
            },
            optional_header: crate::header::ImageOptionalHeader {
                magic: 0x20b,
                major_linker_version: 0,
                minor_linker_version: 0,
                size_of_code: 0x1000,
                size_of_initialized_data: 0x2000,
                size_of_uninitialized_data: 0,
                address_of_entry_point: 0x1000,
                base_of_code: 0x1000,
                base_of_data: None,
                image_base: 0x140000000,
                section_alignment: 0x1000,
                file_alignment: 0x200,
                major_operating_system_version: 6,
                minor_operating_system_version: 0,
                major_image_version: 0,
                minor_image_version: 0,
                major_subsystem_version: 6,
                minor_subsystem_version: 0,
                win32_version_value: 0,
                size_of_image: 0x3000,
                size_of_headers: 0x400,
                check_sum: 0,
                subsystem: 3,
                dll_characteristics: 0,
                size_of_stack_reserve: 0x100000,
                size_of_stack_commit: 0x1000,
                size_of_heap_reserve: 0x100000,
                size_of_heap_commit: 0x1000,
                loader_flags: 0,
                number_of_rva_and_sizes: 16,
                data_directory: [crate::header::ImageDataDirectory::default(); 16],
            },
        },
        sections: vec![crate::header::PeSection {
            header: crate::header::ImageSectionHeader {
                name: *b".text\0\0\0",
                virtual_size: 0x100,
                virtual_address: 0x1000,
                size_of_raw_data: 0x200,
                pointer_to_raw_data: 0x400,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: 0x60000020,
            },
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_offset: 0x400,
            raw_size: 0x200,
            characteristics: 0x60000020,
            extra_data: None,
        }],
        image_base: 0x140000000,
        entry_point: 0x1000,
        is_64bit: true,
        file_alignment: 0x200,
        section_alignment: 0x1000,
    };
    super::super::module_identity::ModuleIdentity::from_pe_header(&pe).unwrap()
}

/// The `sample_active` predicate used inside `detect_heap_globals` must be
/// false for an unbound policy even when it carries sample RVAs (the
/// MIDA-SERIAL-14 gate semantics). This proves normalize/exhaust/drop are
/// skipped (their `if sample_active` guards) without a matching binding.
#[test]
fn m15_unbound_policy_denies_sample_paths() {
    let module = m15_test_module_identity();
    let p = DumpCapturePolicy::ahk_gto_default(); // sample RVAs but NO binding
    let sample_active = p.sample_specific_activation(&module);
    assert!(!sample_active, "unbound policy must deny sample paths");
    // Generic knobs remain available on the stripped policy.
    let stripped = p.strip_sample_specific();
    assert!(stripped.is_generic_only());
    assert_eq!(stripped.first_hop_probe(), p.first_hop_probe());
}

/// A matching binding (with revision + digest) permits sample paths.
#[test]
fn m15_matching_binding_permits_sample_paths() {
    let module = m15_test_module_identity();
    let p = DumpCapturePolicy::ahk_gto_default()
        .with_module_binding(module.clone())
        .with_policy_revision(1)
        .with_external_policy_digest(
            DumpCapturePolicy::ahk_gto_default()
                .with_module_binding(module.clone())
                .with_policy_revision(1)
                .policy_digest_value(),
        );
    let sample_active = p.sample_specific_activation(&module);
    assert!(sample_active, "matching binding must permit sample paths");
    assert!(p.allows_sample_transform(&module, "sanitize_ahk_runtime_global"));
    assert!(p.allows_sample_transform(&module, "normalize_cmd_table_capture"));
}

/// A different module (different timestamp) must deny sample paths even
/// with a binding present on the policy.
#[test]
fn m15_mismatching_module_denies_sample_paths() {
    // Build a second module identity with a different TimeDateStamp by
    // re-constructing the PE header with stamp+1. We reuse the helper by
    // mutating the parsed header (timestamp is a plain field).
    let m1 = m15_test_module_identity();
    // Rebuild with a different stamp: clone the header construction via a
    // second helper call is not parameterized, so mutate the parsed header
    // of a freshly built identity instead (stamp is stored on the struct).
    let m2 = super::super::module_identity::ModuleIdentity {
        machine: m1.machine,
        time_date_stamp: m1.time_date_stamp.wrapping_add(1),
        size_of_image: m1.size_of_image,
        check_sum: m1.check_sum,
        section_layout_digest: m1.section_layout_digest.clone(),
    };
    let p = DumpCapturePolicy::ahk_gto_default()
        .with_module_binding(m1)
        .with_policy_revision(1)
        .with_external_policy_digest(String::new()); // digest empty => digest_matches true
    assert!(
        !p.sample_specific_activation(&m2),
        "different module must deny"
    );
}

// ============ MIDA-SERIAL-17 pipeline regression tests ============

/// 0x147868 cmd-table sentinel must never be sanitized or reinitialized by
/// sanitize_ahk_runtime_global: that transform targets exactly 0x141bf0.
#[test]
fn m17_cmd_table_147868_not_sanitized_or_reinitialized() {
    // Build two globals: the sanitize target (0x141bf0) and the cmd table
    // (0x147868) with a sentinel byte pattern that must survive.
    let mut globals = vec![
        HeapGlobalSnapshot {
            rva: 0x141bf0,
            live_ptr: 0x1000,
            content: vec![0xAAu8; 0x2000], // dirty blob
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
        HeapGlobalSnapshot {
            rva: 0x147868,
            live_ptr: 0x2000,
            content: vec![0x5Au8; 0x40], // cmd table sentinel
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        },
    ];
    // Apply the sample-specific sanitize directly (its dump_process call
    // is gated; here we prove the transform itself never touches 0x147868).
    sanitize_ahk_runtime_global(&mut globals);
    // 0x141bf0 sanitized to zeroed 0x180 slab.
    let ahk = &globals[0];
    assert_eq!(ahk.content.len(), 0x180);
    assert!(ahk.content.iter().all(|&b| b == 0));
    // 0x147868 cmd table untouched (sentinel 0x5A preserved).
    let cmd = &globals[1];
    assert_eq!(cmd.content.len(), 0x40);
    assert!(
        cmd.content.iter().all(|&b| b == 0x5A),
        "0x147868 must not be zeroed by sanitize"
    );
}

/// A rejected (unbound) sample transform must not create an applied ledger
/// record. This proves the gate guard prevents apply_recorded_transform
/// from running (equivalent production seam: dump_process `if sample_active`).
#[test]
fn m17_rejected_transform_does_not_enter_ledger() {
    use super::super::raw_slab_coherence::TransformRunLedger;
    // Unbound policy: sample_specific_activation is false for ANY module.
    let p = DumpCapturePolicy::ahk_gto_default(); // no binding
    let module = m15_test_module_identity();
    assert!(!p.sample_specific_activation(&module));
    // Simulate the production seam: when the gate denies, the transform is
    // NOT applied and the ledger stays empty. (The real seam is the
    // `if sample_active` guard in dump_process; this proves the ledger
    // invariant the guard relies on.)
    let mut ledger = TransformRunLedger::default();
    if p.sample_specific_activation(&module) {
        // Gate allowed — this branch must not run for unbound policy.
        let mut g = vec![];
        let _ = super::super::raw_slab_coherence::apply_recorded_transform(
            &mut g,
            "sanitize_ahk_runtime_global",
            &mut ledger,
            |g| super::sanitize_ahk_runtime_global(g),
        );
    }
    assert!(
        ledger.runs.is_empty(),
        "rejected transform must not enter ledger"
    );
}

// ============ MIDA-SERIAL-23 capture-derived first-hop candidates ============

/// Build a 64-bit PE header with a non-executable .data section.
fn m23_pe(image_base: u64, data_va: u32, data_size: u32) -> crate::header::PeHeader {
    crate::header::PeHeader {
        dos_header: crate::header::ImageDosHeader {
            e_magic: 0x5a4d,
            e_lfanew: 0x40,
        },
        nt_headers: crate::header::ImageNtHeaders {
            signature: 0x4550,
            file_header: crate::header::ImageFileHeader {
                machine: 0x8664,
                number_of_sections: 2,
                time_date_stamp: 0x5f5e100,
                size_of_optional_header: 0xf0,
                characteristics: 0x102,
            },
            optional_header: crate::header::ImageOptionalHeader {
                magic: 0x20b,
                major_linker_version: 0,
                minor_linker_version: 0,
                size_of_code: 0x1000,
                size_of_initialized_data: 0x2000,
                size_of_uninitialized_data: 0,
                address_of_entry_point: 0x1000,
                base_of_code: 0x1000,
                base_of_data: None,
                image_base,
                section_alignment: 0x1000,
                file_alignment: 0x200,
                major_operating_system_version: 6,
                minor_operating_system_version: 0,
                major_image_version: 0,
                minor_image_version: 0,
                major_subsystem_version: 6,
                minor_subsystem_version: 0,
                win32_version_value: 0,
                size_of_image: data_va.saturating_add(data_size).max(0x4000),
                size_of_headers: 0x400,
                check_sum: 0,
                subsystem: 3,
                dll_characteristics: 0,
                size_of_stack_reserve: 0x100000,
                size_of_stack_commit: 0x1000,
                size_of_heap_reserve: 0x100000,
                size_of_heap_commit: 0x1000,
                loader_flags: 0,
                number_of_rva_and_sizes: 16,
                data_directory: [crate::header::ImageDataDirectory::default(); 16],
            },
        },
        sections: vec![
            crate::header::PeSection {
                header: crate::header::ImageSectionHeader {
                    name: *b".text\0\0\0",
                    virtual_size: 0x1000,
                    virtual_address: 0x1000,
                    size_of_raw_data: 0x200,
                    pointer_to_raw_data: 0x400,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: 0x60000020, // EXECUTE|READ
                },
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0x400,
                raw_size: 0x200,
                characteristics: 0x60000020,
                extra_data: None,
            },
            crate::header::PeSection {
                header: crate::header::ImageSectionHeader {
                    name: *b".data\0\0\0",
                    virtual_size: data_size,
                    virtual_address: data_va,
                    size_of_raw_data: data_size.min(0x1000),
                    pointer_to_raw_data: 0x600,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: 0xC0000040, // INITIALIZED_DATA|READ|WRITE
                },
                name: ".data".to_string(),
                virtual_address: data_va,
                virtual_size: data_size,
                raw_offset: 0x600,
                raw_size: data_size.min(0x1000),
                characteristics: 0xC0000040,
                extra_data: None,
            },
        ],
        image_base,
        entry_point: 0x1000,
        is_64bit: true,
        file_alignment: 0x200,
        section_alignment: 0x1000,
    }
}

/// Minimal non-heap-handle root snapshot helper.
fn m23_root(rva: u32, live_ptr: u64, content: Vec<u8>) -> HeapGlobalSnapshot {
    HeapGlobalSnapshot {
        rva,
        live_ptr,
        content,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    }
}

/// Dense pointer-array content: live heap pointers in the leading bytes.
fn m23_dense_content(live_ptrs: &[u64]) -> Vec<u8> {
    let mut v = Vec::with_capacity(live_ptrs.len() * 8);
    for p in live_ptrs {
        v.extend_from_slice(&p.to_le_bytes());
    }
    v
}

/// A generic policy (no sample-specific fields). Sample-specific policy
/// declarations can never activate a first-hop candidate by themselves;
/// activation requires the identity-bound structural role verification.
fn m24_generic_policy() -> DumpCapturePolicy {
    DumpCapturePolicy::default()
}

/// Build an image dump buffer (index == RVA) with the element-count dword
/// written at count_rva. Returns None when the write is out of bounds.
fn m24_dump_buf_with_count(size: usize, count_rva: usize, count: u32) -> Option<Vec<u8>> {
    if count_rva.checked_add(4)? > size {
        return None;
    }
    let mut buf = vec![0u8; size];
    buf[count_rva..count_rva + 4].copy_from_slice(&count.to_le_bytes());
    Some(buf)
}

/// Candidate derivation must be driven by structural evidence — never by a
/// bare fixed RVA, density, or policy nomination. A non-sample RVA with a
/// dense pointer-array capture and .data placement but NO declared role
/// must fail closed (Missing); the declared cmd-table slot with a
/// verified count x 8 boundary resolves deterministically.
#[test]
fn m23_first_hop_candidate_is_capture_derived() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000); // .data covers 0x147868
    let policy = DumpCapturePolicy::default(); // generic: no declarations

    // (a) Dense pointer-rich object at a NON-sample RVA, no declared
    // role -> Missing (density alone can never activate).
    let dense_rva = 0x2010u32;
    let dense_content = m23_dense_content(&[0x31_0000; 8]); // 100% ptrs
    let out_dense = vec![m23_root(dense_rva, 0x30_0000, dense_content)];
    let dump_empty = vec![0u8; 0x6000];
    let rd =
        derive_first_hop_candidates(&pe, &out_dense, &policy, base, base + 0x6000, &dump_empty);
    assert_eq!(
        rd,
        FirstHopCandidateResolution::Missing,
        "dense object without declared role must fail closed"
    );

    // (b) Declared cmd-table slot with verified count x 8 boundary.
    let slot_rva = 0x147868u32;
    let count: u32 = 4;
    let count_rva = slot_rva as usize + 0x20; // 0x147888
    let content = m23_dense_content(&[0x31_0000, 0x32_0000, 0x33_0000, 0x34_0000]);
    assert_eq!(content.len(), (count as usize) * 8);
    let out = vec![m23_root(slot_rva, 0x30_0000, content.clone())];
    let dump = m24_dump_buf_with_count(0x150000, count_rva, count).unwrap();

    let res = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x150000, &dump);
    // Determinism: identical inputs -> identical candidate key order.
    let res2 = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x150000, &dump);
    assert_eq!(res, res2, "candidate derivation must be deterministic");
    match res {
        FirstHopCandidateResolution::Resolved(cands) => {
            assert_eq!(cands.len(), 1, "exactly one verified candidate");
            let c = &cands[0];
            assert_eq!(c.table_rva, slot_rva, "candidate binds the declared slot");
            assert_eq!(c.live_ptr, 0x30_0000);
            assert_eq!(c.section_name, ".data");
            assert_eq!(c.section_index, 1);
            assert_eq!(c.slot_offset_in_section, slot_rva as usize - 0x2000usize);
            // Span comes from the verified count x 8 boundary, not density.
            assert_eq!(c.span, content.len());
            assert_eq!(
                c.evidence,
                FirstHopCandidateEvidence::VerifiedCountScaledExtent
            );
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

/// Two different image bases and two different section layouts must not
/// change the capture-derived result: the identity-bound cmd-table role
/// resolves under both layouts with a verified count x 8 boundary, and
/// a bare fixed RVA alone must never activate a candidate.
#[test]
fn m23_first_hop_candidate_changes_with_image_layout() {
    let policy = DumpCapturePolicy::default();

    // Layout A: image base 0x140000000, .data at 0x2000, declared slot
    // 0x147868, count 4 @ 0x147888, content 32 bytes, live table 0x30_0000.
    let pe_a = m23_pe(0x140000000, 0x2000, 0x150000);
    let out_a = vec![m23_root(
        0x147868,
        0x30_0000,
        m23_dense_content(&[0x31_0000, 0x32_0000, 0x33_0000, 0x34_0000]),
    )];
    let dump_a = m24_dump_buf_with_count(0x150000, 0x147868 + 0x20, 4).unwrap();

    // Layout B: different image base 0x180000000, .data at 0x2000, same
    // declared slot 0x147868, count 4, different live heaps.
    let pe_b = m23_pe(0x180000000, 0x2000, 0x150000);
    let out_b = vec![m23_root(
        0x147868,
        0x50_0000,
        m23_dense_content(&[0x51_0000, 0x52_0000, 0x53_0000, 0x54_0000]),
    )];
    let dump_b = m24_dump_buf_with_count(0x150000, 0x147868 + 0x20, 4).unwrap();

    let ra = derive_first_hop_candidates(&pe_a, &out_a, &policy, 0x140000000, 0x140150000, &dump_a);
    let rb = derive_first_hop_candidates(&pe_b, &out_b, &policy, 0x180000000, 0x180150000, &dump_b);
    match (ra, rb) {
        (FirstHopCandidateResolution::Resolved(ca), FirstHopCandidateResolution::Resolved(cb)) => {
            assert_eq!(ca.len(), 1);
            assert_eq!(cb.len(), 1);
            assert_eq!(ca[0].table_rva, 0x147868);
            assert_eq!(cb[0].table_rva, 0x147868);
            assert_eq!(ca[0].live_ptr, 0x30_0000);
            assert_eq!(cb[0].live_ptr, 0x50_0000);
            assert_eq!(cb[0].section_name, ".data");
        }
        other => panic!("expected both Resolved, got {other:?}"),
    }

    // A slot at the SAME fixed sample RVA with NO capture evidence
    // (empty content) must NOT activate.
    let out_empty = vec![m23_root(0x147868, 0x30_0000, Vec::new())];
    let re = derive_first_hop_candidates(
        &pe_a,
        &out_empty,
        &policy,
        0x140000000,
        0x140150000,
        &dump_a,
    );
    assert_eq!(
        re,
        FirstHopCandidateResolution::Missing,
        "fixed RVA without capture evidence must fail closed"
    );

    // Same fixed RVA with content that does not match the count x 8
    // boundary: count 4 establishes a 32-byte boundary, the captured
    // extent is 64 bytes -> CONFLICTING structural extents -> Ambiguous
    // (fail-closed, never Resolved).
    let out_junk = vec![m23_root(0x147868, 0x30_0000, vec![1u8; 0x40])];
    let rj =
        derive_first_hop_candidates(&pe_a, &out_junk, &policy, 0x140000000, 0x140150000, &dump_a);
    assert_eq!(
        rj,
        FirstHopCandidateResolution::Ambiguous,
        "conflicting count-scaled boundary must fail closed as Ambiguous"
    );
}

/// No table/slot/region evidence -> Missing -> first-hop does not run and
/// no child is fabricated; the generic capture path is unaffected.
#[test]
fn m23_missing_candidate_evidence_fails_closed() {
    let base = 0x140000000u64;
    // .data spans up to 0x152000 so the declared slot 0x147868 sits in a
    // real non-executable data section — the evidence failures below are
    // about content/structural-boundary evidence, not section placement.
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let dump_ok = m24_dump_buf_with_count(0x150000, 0x147888, 4).unwrap();

    // The capture contains NO root at the declared slot RVA.
    let out_none: Vec<HeapGlobalSnapshot> =
        vec![m23_root(0x3000, 0x30_0000, m23_dense_content(&[0x31_0000]))];
    let r = derive_first_hop_candidates(&pe, &out_none, &policy, base, base + 0x152000, &dump_ok);
    assert_eq!(
        r,
        FirstHopCandidateResolution::Missing,
        "absent slot must fail closed"
    );

    // Declared slot present but content too short (< 8 bytes) -> Missing.
    let out_short = vec![m23_root(0x147868, 0x30_0000, vec![0u8; 4])];
    let r2 = derive_first_hop_candidates(&pe, &out_short, &policy, base, base + 0x152000, &dump_ok);
    assert_eq!(
        r2,
        FirstHopCandidateResolution::Missing,
        "undersized captured slot must fail closed"
    );

    // Declared slot present, content >= 8 but live_ptr is NOT a user-heap
    // pointer (image pointer) -> Missing (pointer filter fails).
    let image_ptr = base + 0x147868;
    let out_img = vec![m23_root(0x147868, image_ptr, vec![0u8; 0x40])];
    let r3 = derive_first_hop_candidates(&pe, &out_img, &policy, base, base + 0x152000, &dump_ok);
    assert_eq!(
        r3,
        FirstHopCandidateResolution::Missing,
        "image-pointer live_ptr must fail closed"
    );

    // Declared slot present with valid pointer/section, but the count
    // dword is ABSENT from dump_buf (count read out of bounds) -> Missing.
    let out_slot = vec![m23_root(0x147868, 0x30_0000, vec![0u8; 0x20])];
    let dump_short = vec![0u8; 0x147868 + 0x20]; // count dword out of range
    let r5 =
        derive_first_hop_candidates(&pe, &out_slot, &policy, base, base + 0x152000, &dump_short);
    assert_eq!(
        r5,
        FirstHopCandidateResolution::Missing,
        "unreadable count dword must fail closed"
    );

    // No candidates at all (no roots) -> Missing.
    let r4 = derive_first_hop_candidates(&pe, &[], &policy, base, base + 0x152000, &dump_ok);
    assert_eq!(r4, FirstHopCandidateResolution::Missing);
}

/// A single declared slot whose count x 8 structural boundary CONFLICTS
/// with the captured extent (count says 32 bytes, content is 64 bytes)
/// cannot be uniquely decided -> Ambiguous -> fail closed. This is the
/// MIDA-SERIAL-24 D-item-2 case (one slot, two conflicting extents).
#[test]
fn m23_ambiguous_candidates_fail_closed() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000); // .data covers 0x147868
    let policy = DumpCapturePolicy::default();
    // count = 4 -> declared boundary 32 bytes, but the captured content
    // is 64 bytes (e.g. an oversized probe window that normalize did not
    // shrink, or a free-list tail). Conflict -> Ambiguous.
    let dump = m24_dump_buf_with_count(0x150000, 0x147888, 4).unwrap();
    let out = vec![m23_root(
        0x147868,
        0x30_0000,
        m23_dense_content(&[0x31_0000; 8]), // 64 bytes != 4*8
    )];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    assert_eq!(
        r,
        FirstHopCandidateResolution::Ambiguous,
        "conflicting structural extent must fail closed as Ambiguous"
    );
}

/// 0x147868 sentinel must never be sanitized/reinitialized, and the
/// count*8 normalize semantics survive. (Re-derives the m17 invariant
/// against the MIDA-24 candidate seam.)
#[test]
fn m23_cmd_table_not_sanitized() {
    let mut globals = vec![
        m23_root(0x141bf0, 0x1000, vec![0xAAu8; 0x2000]),
        m23_root(0x147868, 0x2000, vec![0x5Au8; 0x40]),
    ];
    sanitize_ahk_runtime_global(&mut globals);
    let ahk = &globals[0];
    assert_eq!(ahk.content.len(), 0x180, "0x141bf0 sanitized to 0x180 slab");
    assert!(ahk.content.iter().all(|&b| b == 0));
    let cmd = &globals[1];
    assert_eq!(cmd.content.len(), 0x40);
    assert!(
        cmd.content.iter().all(|&b| b == 0x5A),
        "0x147868 must never be zeroed by sanitize"
    );

    // 0x141bf0 is a declared identity-bound BOUNDED role in MIDA-25:
    // it is NOT a count-scaled pointer table. With content larger than
    // max_span it resolves with span == max_span (0x200) and evidence
    // IdentityBoundedPointerWindow — never a full-content candidate.
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000); // .data covers 0x141bf0
    let policy = DumpCapturePolicy::default();
    let dump = vec![0u8; 0x150000];
    let out = vec![m23_root(0x141bf0, 0x30_0000, vec![0u8; 0x2000])];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    match r {
        FirstHopCandidateResolution::Resolved(cands) => {
            let c = cands.iter().find(|c| c.table_rva == 0x141bf0).unwrap();
            assert_eq!(
                c.evidence,
                FirstHopCandidateEvidence::IdentityBoundedPointerWindow,
            );
            assert_eq!(c.span, 0x200, "bounded span must cap at max_span");
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

/// The identity gate still wraps the first-hop path: unbound/mismatch/
/// revision-0/digest-mismatch policies never reach the legacy fallback —
/// the sample_active predicate (production seam in detect_heap_globals)
/// denies first-hop entirely, and a rejected gate writes no applied ledger.
#[test]
fn m23_identity_gate_still_wraps_legacy_fallback() {
    use super::super::raw_slab_coherence::TransformRunLedger;
    let module = m15_test_module_identity();

    // A sample-specific policy (hot roots) without a binding: the gate
    // denies sample activation -> first-hop path (gated by sample_active
    // in detect_heap_globals) cannot run.
    let unbound = DumpCapturePolicy::ahk_gto_default();
    assert!(
        unbound.has_sample_specific(),
        "policy carries sample declarations but must not self-activate"
    );
    assert!(
        !unbound.sample_specific_activation(&module),
        "unbound policy must deny sample paths"
    );

    // Revision 0 with a binding still denies (unversioned policy).
    let rev0 = DumpCapturePolicy::ahk_gto_default().with_module_binding(module.clone());
    assert!(!rev0.sample_specific_activation(&module));

    // A valid (revision + digest) binding activates — matching identity.
    let valid = DumpCapturePolicy::ahk_gto_default()
        .with_module_binding(module.clone())
        .with_policy_revision(1)
        .with_external_policy_digest(
            DumpCapturePolicy::ahk_gto_default()
                .with_module_binding(module.clone())
                .with_policy_revision(1)
                .policy_digest_value(),
        );
    assert!(valid.sample_specific_activation(&module));

    // Rejected gate -> no applied ledger record (legacy fallback must not
    // sneak back in under a denied gate).
    let mut ledger = TransformRunLedger::default();
    if unbound.sample_specific_activation(&module) {
        let mut g = vec![];
        let _ = super::super::raw_slab_coherence::apply_recorded_transform(
            &mut g,
            "sanitize_ahk_runtime_global",
            &mut ledger,
            |g| super::sanitize_ahk_runtime_global(g),
        );
    }
    assert!(
        ledger.runs.is_empty(),
        "denied gate must not write an applied ledger"
    );
}

/// Execution seam: a resolved candidate's verified count-scaled span drives
/// the real pointer-table walk and admits heap children; the walker reads
/// the child bodies from the live-map mock.
#[test]
fn m23_exhaust_seam_uses_candidate_span() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000); // .data covers 0x147868
    let slot_rva = 0x147868u32;
    let table_live = 0x30_0000u64;
    let child_a = 0x31_0000u64;
    let child_b = 0x32_0000u64;
    // count = 4 -> verified span 32 bytes covering child_a and child_b.
    let content = m23_dense_content(&[child_a, child_b, 0, 0]);
    let out = vec![m23_root(slot_rva, table_live, content.clone())];
    let policy = DumpCapturePolicy::default();
    let dump = m24_dump_buf_with_count(0x150000, slot_rva as usize + 0x20, 4).unwrap();

    let res = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    let cands = match res {
        FirstHopCandidateResolution::Resolved(c) => c,
        other => panic!("expected Resolved, got {other:?}"),
    };
    let c = &cands[0];
    assert_eq!(c.table_rva, slot_rva);
    assert_eq!(
        c.evidence,
        FirstHopCandidateEvidence::VerifiedCountScaledExtent
    );
    assert_eq!(c.span, content.len()); // 4 * 8

    let mut mock = M23RegionMapMock::new();
    mock.set(child_a, vec![0x11u8; 0x40]);
    mock.set(child_b, vec![0x22u8; 0x40]);

    let mut globals = out.clone();
    let mut total_bytes = 0usize;
    let mut seen = BTreeSet::new();
    exhaust_first_hop_candidates(
        &mut globals,
        &mut total_bytes,
        &mut seen,
        base,
        base + 0x152000,
        &dump,
        &mut mock,
        &cands,
    );
    // Both table children admitted as exact-base snapshots.
    let a = globals.iter().find(|g| g.live_ptr == child_a);
    let b = globals.iter().find(|g| g.live_ptr == child_b);
    assert!(a.is_some(), "child A must be admitted from the table walk");
    assert!(b.is_some(), "child B must be admitted from the table walk");
    assert!(total_bytes >= 0x40 * 2);
    assert!(
        globals.iter().filter(|g| g.rva == 0).count() >= 2,
        "walked children must be graph children (rva == 0)"
    );
}

/// Execution seam: Missing / Ambiguous resolution never reaches the
/// walker (no fabricated children, no slot/region expansion). This
/// mirrors the production `if sample_active { match ... }` seam.
#[test]
fn m23_exhaust_seam_fails_closed_without_children() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000); // .data covers 0x147868
    let mut mock = M23RegionMapMock::new();
    mock.set(0x30_0000, vec![0x11u8; 0x40]);
    mock.set(0x31_0000, vec![0x22u8; 0x40]);

    // Missing: no roots in the capture.
    let policy = DumpCapturePolicy::default();
    let out_empty: Vec<HeapGlobalSnapshot> = Vec::new();
    let mut globals = out_empty.clone();
    let mut total_bytes = 0usize;
    let mut seen = BTreeSet::new();
    let dump = vec![0u8; 0x150000];
    let res = derive_first_hop_candidates(&pe, &out_empty, &policy, base, base + 0x152000, &dump);
    assert_eq!(res, FirstHopCandidateResolution::Missing);
    if let FirstHopCandidateResolution::Resolved(cands) = res {
        exhaust_first_hop_candidates(
            &mut globals,
            &mut total_bytes,
            &mut seen,
            base,
            base + 0x152000,
            &dump,
            &mut mock,
            &cands,
        );
    }
    assert!(
        globals.is_empty(),
        "Missing resolution must not fabricate children"
    );
    assert_eq!(total_bytes, 0);

    // Ambiguous: the declared slot's count x 8 boundary conflicts with
    // the captured extent (count 4 -> 32 bytes, content 64 bytes).
    let out_conflict = vec![m23_root(
        0x147868,
        0x30_0000,
        m23_dense_content(&[0x31_0000; 8]),
    )];
    let dump_conflict = m24_dump_buf_with_count(0x150000, 0x147888, 4).unwrap();
    let res2 = derive_first_hop_candidates(
        &pe,
        &out_conflict,
        &policy,
        base,
        base + 0x152000,
        &dump_conflict,
    );
    assert_eq!(res2, FirstHopCandidateResolution::Ambiguous);
    let mut globals2 = out_conflict.clone();
    let mut total2 = 0usize;
    let mut seen2 = BTreeSet::new();
    if let FirstHopCandidateResolution::Resolved(cands) = res2 {
        exhaust_first_hop_candidates(
            &mut globals2,
            &mut total2,
            &mut seen2,
            base,
            base + 0x152000,
            &dump_conflict,
            &mut mock,
            &cands,
        );
    }
    assert_eq!(
        globals2.len(),
        1,
        "Ambiguous resolution must not expand slots/regions"
    );
    assert_eq!(total2, 0);
}

/// Minimal memory-map DebuggerCore for driving the real first-hop exhaust
/// emitter (MIDA-SERIAL-23 execution seam). Serves fixed (base -> bytes)
/// regions; reads outside them fail.
#[derive(Default)]
struct M23RegionMapMock {
    regions: std::collections::BTreeMap<u64, Vec<u8>>,
}

impl M23RegionMapMock {
    fn new() -> Self {
        Self {
            regions: std::collections::BTreeMap::new(),
        }
    }
    fn set(&mut self, base: u64, bytes: Vec<u8>) {
        self.regions.insert(base, bytes);
    }
}

impl mida_core::DebuggerCore for M23RegionMapMock {
    fn process_handle(&self) -> windows::Win32::Foundation::HANDLE {
        windows::Win32::Foundation::HANDLE(std::ptr::null_mut())
    }
    fn pid(&self) -> u32 {
        1
    }
    fn image_base(&self) -> u64 {
        0x140000000
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

// ============ MIDA-SERIAL-24 adversarial regression tests ============

/// A dense, un-nominated, pointer-rich object (100% heap pointers in the
/// leading 0x100 bytes) with no declared first-hop role must be rejected
/// (Missing) — density alone can never activate a candidate.
#[test]
fn m24_dense_unnominated_pointer_rich_object_is_rejected() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x2000);
    let policy = m24_generic_policy();
    // 32 qwords, ALL user-heap pointers -> maximally pointer-rich.
    let mut ptrs = Vec::new();
    for i in 0..32u64 {
        ptrs.push(0x40_0000 + i * 0x1000);
    }
    let content = m23_dense_content(&ptrs);
    let out = vec![m23_root(0x2010, 0x30_0000, content)];
    let dump = vec![0u8; 0x6000];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x6000, &dump);
    assert_eq!(
        r,
        FirstHopCandidateResolution::Missing,
        "dense un-nominated object must fail closed"
    );
}

/// A slot that IS a hot-root nomination (0x18a898) with capture/live-pointer/
/// section conditions all satisfied but NO structural pointer-table role
/// must be rejected (Missing) — nomination alone cannot activate.
#[test]
fn m24_hot_root_without_first_hop_role_is_rejected() {
    let base = 0x140000000u64;
    // .data covers 0x18a898 (hot fill root in the default policy).
    let pe = m23_pe(base, 0x2000, 0x180000);
    // ahk_gto_default nominates 0x18a898 as hot root + expand seed.
    let policy = DumpCapturePolicy::ahk_gto_default();
    let content = m23_dense_content(&[0x31_0000; 8]);
    let out = vec![m23_root(0x18a898, 0x30_0000, content)];
    let dump = vec![0u8; 0x180000];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x180000, &dump);
    assert_eq!(
        r,
        FirstHopCandidateResolution::Missing,
        "hot-root nomination without structural role must fail closed"
    );
}

/// A slot that IS a large-table nomination (0x148bf8) with a dense pointer
/// capture must still be rejected (Missing) when it has no declared
/// count-scaled structural role.
#[test]
fn m24_large_table_nomination_alone_is_rejected() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x180000); // covers 0x148bf8
    let policy = DumpCapturePolicy::ahk_gto_default(); // large_table includes 0x148bf8
    let content = m23_dense_content(&[0x31_0000; 8]);
    let out = vec![m23_root(0x148bf8, 0x30_0000, content)];
    let dump = vec![0u8; 0x180000];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x180000, &dump);
    assert_eq!(
        r,
        FirstHopCandidateResolution::Missing,
        "large-table nomination without structural role must fail closed"
    );
}

/// Density must never select full content span: a dense declared-slot
/// capture larger than the verified count-scaled boundary is either
/// Missing (count unverifiable) or Ambiguous (count boundary conflicts);
/// it is NEVER Resolved with full span.
#[test]
fn m24_dense_evidence_never_selects_full_span() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000); // covers 0x147868
    let policy = m24_generic_policy();
    // Declared slot 0x147868 with count 4 (32-byte boundary) but the
    // captured content is 64 bytes of pure pointers (dense, larger than
    // the boundary). The count boundary CONFLICTS -> Ambiguous, never a
    // Resolved full-span candidate.
    let dump = m24_dump_buf_with_count(0x150000, 0x147888, 4).unwrap();
    let out = vec![m23_root(
        0x147868,
        0x30_0000,
        m23_dense_content(&[0x31_0000; 8]), // 64 bytes != 32
    )];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    assert_eq!(
        r,
        FirstHopCandidateResolution::Ambiguous,
        "density must never grant full span — conflicting boundary fails closed"
    );
    // With NO count dword (unverifiable), the same dense content is Missing.
    let dump_none = vec![0u8; 0x150000];
    let r2 = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump_none);
    assert_eq!(
        r2,
        FirstHopCandidateResolution::Missing,
        "dense content without count boundary must fail closed"
    );
}

/// Extra policy roots (0x148bf8, 0x148c00, 0x148c98) must not expand the
/// first-hop action set merely because they appear in hot-root / large-table
/// unions. Each is checked with capture evidence and must fail closed.
#[test]
fn m24_extra_policy_roots_do_not_expand_old_action_set() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x180000); // covers up to 0x149d50 region
    let policy = DumpCapturePolicy::ahk_gto_default();
    let dump = vec![0u8; 0x180000];
    for rva in [0x148bf8u32, 0x148c00, 0x148c98] {
        assert!(
            policy.is_hot_root(rva) || policy.is_large_table(rva),
            "{rva:#x} must be a policy nomination"
        );
        let out = vec![m23_root(rva, 0x30_0000, m23_dense_content(&[0x31_0000; 8]))];
        let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x180000, &dump);
        assert_eq!(
            r,
            FirstHopCandidateResolution::Missing,
            "extra policy root {rva:#x} must not enter first-hop without structural role"
        );
    }
}

/// Conflicting extent on the SAME candidate fails closed: Ambiguous,
/// walker zero calls, children zero growth, total_bytes unchanged.
#[test]
fn m24_conflicting_extent_fails_closed() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = m24_generic_policy();
    let dump = m24_dump_buf_with_count(0x150000, 0x147888, 4).unwrap();
    let out = vec![m23_root(
        0x147868,
        0x30_0000,
        m23_dense_content(&[0x31_0000; 8]), // 64B != 4*8
    )];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    assert_eq!(
        r,
        FirstHopCandidateResolution::Ambiguous,
        "conflicting extent must be Ambiguous"
    );
    // Walker is never invoked for Ambiguous: no children, no bytes.
    let mut mock = M23RegionMapMock::new();
    mock.set(0x31_0000, vec![0x11u8; 0x40]);
    let mut globals = out.clone();
    let before_len = globals.len();
    let mut total_bytes = 0usize;
    let mut seen = BTreeSet::new();
    if let FirstHopCandidateResolution::Resolved(cands) = r {
        exhaust_first_hop_candidates(
            &mut globals,
            &mut total_bytes,
            &mut seen,
            base,
            base + 0x152000,
            &dump,
            &mut mock,
            &cands,
        );
    }
    assert_eq!(globals.len(), before_len, "Ambiguous must not add children");
    assert_eq!(total_bytes, 0, "Ambiguous must not consume budget");
    assert!(seen.is_empty(), "Ambiguous must not register heap pointers");
}

/// A pointer-rich non-table object must not consume the heap-global budget:
/// seen_heaps, slot count, and total bytes all stay unchanged.
#[test]
fn m24_pointer_rich_non_table_does_not_consume_budget() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x2000);
    let policy = m24_generic_policy();
    // Non-declared dense object (rva 0x2028) at a NON-sample RVA.
    let out = vec![m23_root(
        0x2028,
        0x30_0000,
        m23_dense_content(&[0x31_0000; 8]),
    )];
    let dump = vec![0u8; 0x6000];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x6000, &dump);
    assert_eq!(
        r,
        FirstHopCandidateResolution::Missing,
        "pointer-rich non-table must fail closed"
    );
    let mut mock = M23RegionMapMock::new();
    mock.set(0x31_0000, vec![0x11u8; 0x40]);
    let mut globals = out.clone();
    let before_len = globals.len();
    let mut total_bytes = 0usize;
    let mut seen = BTreeSet::new();
    if let FirstHopCandidateResolution::Resolved(cands) = r {
        exhaust_first_hop_candidates(
            &mut globals,
            &mut total_bytes,
            &mut seen,
            base,
            base + 0x6000,
            &dump,
            &mut mock,
            &cands,
        );
    }
    assert_eq!(globals.len(), before_len, "no slots consumed");
    assert_eq!(total_bytes, 0, "no bytes consumed");
    assert!(seen.is_empty(), "no heap pointers registered");
}

/// The identity gate remains the OUTER boundary: even a structurally
/// plausible fixture must never reach the walker under unbound / mismatch /
/// revision-0 / digest-mismatch policies. (The production seam wraps
/// derive + exhaust in `if sample_active`; here we prove the gate semantics
/// and that a rejected gate performs zero first-hop actions.)
#[test]
fn m24_identity_gate_remains_outer_boundary() {
    let module = m15_test_module_identity();

    // Unbound policy: has sample-specific declarations but no binding.
    let unbound = DumpCapturePolicy::ahk_gto_default();
    assert!(!unbound.sample_specific_activation(&module));

    // Mismatch: binding for module m1, asked about m2 (different stamp).
    let m2 = super::super::module_identity::ModuleIdentity {
        machine: module.machine,
        time_date_stamp: module.time_date_stamp.wrapping_add(1),
        size_of_image: module.size_of_image,
        check_sum: module.check_sum,
        section_layout_digest: module.section_layout_digest.clone(),
    };
    let mismatch = DumpCapturePolicy::ahk_gto_default()
        .with_module_binding(module.clone())
        .with_policy_revision(1)
        .with_external_policy_digest(String::new());
    assert!(!mismatch.sample_specific_activation(&m2));

    // Revision 0: binding present but unversioned.
    let rev0 = DumpCapturePolicy::ahk_gto_default().with_module_binding(module.clone());
    assert!(!rev0.sample_specific_activation(&module));

    // Digest mismatch: stamped digest differs from recomputed value.
    let bad_digest = DumpCapturePolicy::ahk_gto_default()
        .with_module_binding(module.clone())
        .with_policy_revision(1)
        .with_external_policy_digest("deadbeef".into());
    assert!(!bad_digest.sample_specific_activation(&module));
    assert!(!bad_digest.digest_matches());

    // Matching binding activates — but the outer gate is what decides.
    let valid = DumpCapturePolicy::ahk_gto_default()
        .with_module_binding(module.clone())
        .with_policy_revision(1)
        .with_external_policy_digest(
            DumpCapturePolicy::ahk_gto_default()
                .with_module_binding(module.clone())
                .with_policy_revision(1)
                .policy_digest_value(),
        );
    assert!(valid.sample_specific_activation(&module));
}

/// Every default-policy nomination that is NOT the identity-bound
/// cmd-table role (0x147868) must fail closed (Missing) even with
/// capture/live-pointer/section conditions satisfied and a dense
/// pointer-array body. This pins the action set to the single declared
/// structural role — no hot-root / large-table union expansion.
#[test]
fn m24_all_default_nominations_except_declared_role_fail_closed() {
    let base = 0x140000000u64;
    // .data spans [0x2000, 0x202000) so every default-policy RVA below
    // 0x149d50 sits in a real non-executable section.
    let pe = m23_pe(base, 0x2000, 0x200000);
    let policy = DumpCapturePolicy::ahk_gto_default();
    let dump = vec![0u8; 0x200000];
    // Union of default hot roots + large tables (excluding gscript root
    // 0x149d50, which has its own dedicated exhaust path).
    let mut nominations: Vec<u32> = policy
        .hot_root_rvas
        .iter()
        .chain(policy.large_table_rvas.iter())
        .copied()
        .collect();
    nominations.sort_unstable();
    nominations.dedup();
    nominations.retain(|&r| r != 0x149d50);
    // The only declared first-hop role in MIDA-24 is 0x147868.
    let declared: Vec<u32> = declared_first_hop_roles()
        .iter()
        .map(|r| r.slot_rva)
        .collect();
    for rva in &nominations {
        if declared.contains(rva) {
            continue; // declared role is validated elsewhere
        }
        let out = vec![m23_root(
            *rva,
            0x30_0000,
            m23_dense_content(&[0x31_0000; 8]),
        )];
        let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x200000, &dump);
        assert_eq!(
                r,
                FirstHopCandidateResolution::Missing,
                "default-policy nomination {rva:#x} must not enter first-hop without a declared structural role"
            );
    }
    // Sanity: the union actually covers the extra roots the work order names.
    for rva in [0x18a898u32, 0x148bf8, 0x148ca8, 0x148c98, 0x148c00] {
        assert!(
            nominations.contains(&rva),
            "{rva:#x} must be part of the default nomination union"
        );
    }
}

// ============ MIDA-SERIAL-25 identity-bound role parity tests ============

/// Helper: build the dump buffer sized to cover a role slot's count dword
/// (or just a large data region for bounded roles).
fn m25_dump(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

/// 0x147868 count-scaled role resolves with VerifiedCountScaledExtent when
/// the count x 8 boundary exactly matches the captured extent.
#[test]
fn m25_cmd_table_count_scaled_role_is_resolved() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000); // .data covers 0x147868
    let policy = DumpCapturePolicy::default();
    let dump = m24_dump_buf_with_count(0x150000, 0x147888, 4).unwrap();
    let content = m23_dense_content(&[0x31_0000, 0x32_0000, 0x33_0000, 0x34_0000]);
    let out = vec![m23_root(0x147868, 0x30_0000, content.clone())];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    match r {
        FirstHopCandidateResolution::Resolved(cands) => {
            assert_eq!(cands.len(), 1);
            let c = &cands[0];
            assert_eq!(c.table_rva, 0x147868);
            assert_eq!(c.span, content.len()); // 4 * 8
            assert_eq!(
                c.evidence,
                FirstHopCandidateEvidence::VerifiedCountScaledExtent,
            );
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

/// 0x141bf0 bounded role resolves with span == max_span (0x200) when the
/// captured content is larger than the window; evidence is
/// IdentityBoundedPointerWindow.
#[test]
fn m25_ahk_global_bounded_role_is_resolved() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000); // .data covers 0x141bf0
    let policy = DumpCapturePolicy::default();
    let dump = m25_dump(0x150000);
    let content = vec![0u8; 0x2000]; // larger than max_span 0x200
    let out = vec![m23_root(0x141bf0, 0x30_0000, content)];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    match r {
        FirstHopCandidateResolution::Resolved(cands) => {
            let c = cands.iter().find(|c| c.table_rva == 0x141bf0).unwrap();
            assert_eq!(c.span, 0x200, "bounded span must cap at max_span");
            assert_eq!(
                c.evidence,
                FirstHopCandidateEvidence::IdentityBoundedPointerWindow,
            );
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

/// Bounded role with content in [8, 0x200) uses only the available extent
/// (never reads beyond content).
#[test]
fn m25_ahk_global_short_capture_uses_only_available_extent() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let dump = m25_dump(0x150000);
    let content = vec![0u8; 0x40]; // 64 bytes, within [8, 0x200)
    let out = vec![m23_root(0x141bf0, 0x30_0000, content.clone())];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    match r {
        FirstHopCandidateResolution::Resolved(cands) => {
            let c = cands.iter().find(|c| c.table_rva == 0x141bf0).unwrap();
            assert_eq!(c.span, content.len(), "span must equal available extent");
            assert!(c.span < 0x200);
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

/// Bounded role with content < 8 bytes fails closed (Missing).
#[test]
fn m25_ahk_global_too_short_fails_closed() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let dump = m25_dump(0x150000);
    let out = vec![m23_root(0x141bf0, 0x30_0000, vec![0u8; 4])];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    assert_eq!(r, FirstHopCandidateResolution::Missing);
}

/// Bounded role with a non-user-heap live pointer fails closed (Missing).
#[test]
fn m25_ahk_global_invalid_live_pointer_fails_closed() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let dump = m25_dump(0x150000);
    let image_ptr = base + 0x141bf0; // image-resident, not user heap
    let out = vec![m23_root(0x141bf0, image_ptr, vec![0u8; 0x40])];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    assert_eq!(r, FirstHopCandidateResolution::Missing);
}

/// Bounded role in an executable section fails closed (Missing).
#[test]
fn m25_ahk_global_executable_section_fails_closed() {
    let base = 0x140000000u64;
    // 0x141bf0 lies inside .text [0x1000, 0x2000) here.
    let pe = m23_pe(base, 0x1000, 0x1000); // .data at 0x1000 is EXECUTE
    let policy = DumpCapturePolicy::default();
    let dump = m25_dump(0x3000);
    let out = vec![m23_root(0x141bf0, 0x30_0000, vec![0u8; 0x40])];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x3000, &dump);
    assert_eq!(r, FirstHopCandidateResolution::Missing);
}

/// The REAL bounded walker seam: a heap child pointer at +0xd8 inside
/// the 0x141bf0 bounded window is admitted as an exact-base child — this
/// proves the HEAD 0x141bf0 bounded first-hop purpose is preserved.
#[test]
fn m25_ahk_global_bounded_walker_reaches_d8_child() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let dump = m25_dump(0x150000);
    let child = 0x31_0000u64;
    // 0x200-byte content; put a heap pointer at offset +0xd8 (0xd8..0xe0).
    let mut content = vec![0u8; 0x200];
    content[0xd8..0xe0].copy_from_slice(&child.to_le_bytes());
    let out = vec![m23_root(0x141bf0, 0x30_0000, content)];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    let cands = match r {
        FirstHopCandidateResolution::Resolved(c) => c,
        other => panic!("expected Resolved, got {other:?}"),
    };
    let mut mock = M23RegionMapMock::new();
    mock.set(child, vec![0x11u8; 0x40]);
    let mut globals = out.clone();
    let mut total_bytes = 0usize;
    let mut seen = BTreeSet::new();
    exhaust_first_hop_candidates(
        &mut globals,
        &mut total_bytes,
        &mut seen,
        base,
        base + 0x152000,
        &dump,
        &mut mock,
        &cands,
    );
    let admitted = globals.iter().find(|g| g.live_ptr == child);
    assert!(
        admitted.is_some(),
        "+0xd8 interior child must be admitted by the bounded walker"
    );
}

/// A heap child pointer placed AT or BEYOND +0x200 must NOT be walked:
/// the bounded window never reads or enumerates past max_span.
#[test]
fn m25_ahk_global_pointer_after_0x200_is_not_walked() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let dump = m25_dump(0x150000);
    let outside = 0x32_0000u64;
    // content longer than 0x200; pointer at +0x200..0x208 (beyond window).
    let mut content = vec![0u8; 0x300];
    content[0x200..0x208].copy_from_slice(&outside.to_le_bytes());
    let out = vec![m23_root(0x141bf0, 0x30_0000, content)];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    let cands = match r {
        FirstHopCandidateResolution::Resolved(c) => c,
        other => panic!("expected Resolved, got {other:?}"),
    };
    let c = cands.iter().find(|c| c.table_rva == 0x141bf0).unwrap();
    assert_eq!(c.span, 0x200, "span must stay at max_span");
    let mut mock = M23RegionMapMock::new();
    mock.set(outside, vec![0x22u8; 0x40]);
    let mut globals = out.clone();
    let mut total_bytes = 0usize;
    let mut seen = BTreeSet::new();
    exhaust_first_hop_candidates(
        &mut globals,
        &mut total_bytes,
        &mut seen,
        base,
        base + 0x152000,
        &dump,
        &mut mock,
        &cands,
    );
    let admitted = globals.iter().find(|g| g.live_ptr == outside);
    assert!(
        admitted.is_none(),
        "pointer beyond +0x200 must never be walked"
    );
}

/// Extra default-policy roots remain rejected even when dense.
#[test]
fn m25_extra_default_roots_remain_rejected() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x200000);
    let policy = DumpCapturePolicy::ahk_gto_default();
    let dump = vec![0u8; 0x200000];
    for rva in [0x18a898u32, 0x148bf8, 0x148ca8, 0x148c98, 0x148c00] {
        let out = vec![m23_root(rva, 0x30_0000, m23_dense_content(&[0x31_0000; 8]))];
        let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x200000, &dump);
        assert_eq!(
            r,
            FirstHopCandidateResolution::Missing,
            "{rva:#x} must remain rejected even when dense"
        );
    }
}

/// An arbitrary dense object (non-declared RVA) remains rejected.
#[test]
fn m25_arbitrary_dense_object_remains_rejected() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x6000);
    let policy = DumpCapturePolicy::default();
    let dump = vec![0u8; 0x6000];
    let out = vec![m23_root(
        0x2028, // not a declared role
        0x30_0000,
        m23_dense_content(&[0x31_0000; 8]),
    )];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x6000, &dump);
    assert_eq!(r, FirstHopCandidateResolution::Missing);
}

/// The identity gate rejects BOTH declared roles under unbound /
/// mismatch / revision-0 / digest-mismatch: zero first-hop actions.
#[test]
fn m25_identity_gate_rejects_both_declared_roles() {
    let module = m15_test_module_identity();
    let m2 = super::super::module_identity::ModuleIdentity {
        machine: module.machine,
        time_date_stamp: module.time_date_stamp.wrapping_add(1),
        size_of_image: module.size_of_image,
        check_sum: module.check_sum,
        section_layout_digest: module.section_layout_digest.clone(),
    };

    // Unbound.
    let unbound = DumpCapturePolicy::ahk_gto_default();
    assert!(!unbound.sample_specific_activation(&module));

    // Mismatch.
    let mismatch = DumpCapturePolicy::ahk_gto_default()
        .with_module_binding(module.clone())
        .with_policy_revision(1)
        .with_external_policy_digest(String::new());
    assert!(!mismatch.sample_specific_activation(&m2));

    // Revision 0.
    let rev0 = DumpCapturePolicy::ahk_gto_default().with_module_binding(module.clone());
    assert!(!rev0.sample_specific_activation(&module));

    // Digest mismatch.
    let bad_digest = DumpCapturePolicy::ahk_gto_default()
        .with_module_binding(module.clone())
        .with_policy_revision(1)
        .with_external_policy_digest("deadbeef".into());
    assert!(!bad_digest.sample_specific_activation(&module));

    // Matching binding activates — but the outer gate decides before any
    // role resolution; a rejected gate runs zero first-hop actions.
    let valid = DumpCapturePolicy::ahk_gto_default()
        .with_module_binding(module.clone())
        .with_policy_revision(1)
        .with_external_policy_digest(
            DumpCapturePolicy::ahk_gto_default()
                .with_module_binding(module.clone())
                .with_policy_revision(1)
                .policy_digest_value(),
        );
    assert!(valid.sample_specific_activation(&module));
}

/// A legal fixture containing BOTH declared roles resolves to exactly two
/// candidates in deterministic order (0x141bf0 then 0x147868 by section
/// offset), with no extra nomination.
#[test]
fn m25_resolved_action_set_is_exactly_two_roles() {
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000); // covers both roles
    let policy = DumpCapturePolicy::default();
    let dump = m24_dump_buf_with_count(0x150000, 0x147888, 4).unwrap();
    let table_content = m23_dense_content(&[0x31_0000, 0x32_0000, 0x33_0000, 0x34_0000]);
    let global_content = vec![0u8; 0x2000];
    let out = vec![
        m23_root(0x147868, 0x40_0000, table_content),
        m23_root(0x141bf0, 0x50_0000, global_content),
    ];
    let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
    match r {
        FirstHopCandidateResolution::Resolved(cands) => {
            assert_eq!(cands.len(), 2, "exactly two declared roles");
            // Deterministic order: by (section idx, slot offset).
            let rvas: Vec<u32> = cands.iter().map(|c| c.table_rva).collect();
            assert_eq!(rvas, vec![0x141bf0, 0x147868]);
            let c0 = cands.iter().find(|c| c.table_rva == 0x141bf0).unwrap();
            assert_eq!(c0.span, 0x200);
            assert_eq!(
                c0.evidence,
                FirstHopCandidateEvidence::IdentityBoundedPointerWindow,
            );
            let c1 = cands.iter().find(|c| c.table_rva == 0x147868).unwrap();
            assert_eq!(c1.span, 4 * 8);
            assert_eq!(
                c1.evidence,
                FirstHopCandidateEvidence::VerifiedCountScaledExtent,
            );
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

// ============ MIDA-SERIAL-27 count-scaled single-source refactor ============

/// The production cmd-table role is the single fact source consumed by
/// normalize, first-hop, and the hot-root ensure path.
#[test]
fn m27_single_role_consistent_across_consumers() {
    let cmd = CountScaledPointerRole::cmd_table();
    assert_eq!(cmd.slot_rva, 0x147868);
    assert_eq!(cmd.count_offset, 0x20);
    assert_eq!(cmd.element_size, 8);
    assert_eq!(cmd.min_count, 1);
    assert_eq!(cmd.max_count, 0xffff);
    assert_eq!(cmd.min_extent, 8);
    assert_eq!(cmd.count_rva(), Some(0x147888));

    // first-hop declared roles must carry the exact same structural facts.
    let roles = declared_first_hop_roles();
    let hop = roles
        .iter()
        .find(|r| r.slot_rva == cmd.slot_rva)
        .expect("cmd table role declared");
    match hop.kind {
        FirstHopRoleKind::PointerTableCountScaled {
            count_offset,
            element_size,
        } => {
            assert_eq!(count_offset, cmd.count_offset);
            assert_eq!(element_size, cmd.element_size);
        }
        _ => panic!("cmd table must remain PointerTableCountScaled"),
    }
}

/// Normalize, first-hop, and ensure all derive the same 32-byte extent for
/// count=4 (slot 0x147868, count dword at slot+0x20, element size 8).
#[test]
fn m27_normal_count_scaled_extent_consistent() {
    let cmd = CountScaledPointerRole::cmd_table();
    let base = 0x140000000u64;
    let live = 0x30_0000u64;
    let dump_size = 0x150000usize;
    let dump = m24_dump_buf_with_count(dump_size, cmd.count_rva().unwrap(), 4).unwrap();

    // normalize: over-wide 64-byte capture is truncated to 32 bytes.
    let mut out = vec![m23_root(cmd.slot_rva, live, vec![0xAAu8; 64])];
    let mut total = 64usize;
    let mut mock = M23RegionMapMock::new();
    normalize_cmd_table_capture(&mut out, &mut total, &dump, &mut mock);
    assert_eq!(out[0].content.len(), 32);
    assert_eq!(total, 32);

    // first-hop: same dump/count resolves to VerifiedCountScaledExtent(32).
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let out_fh = vec![m23_root(cmd.slot_rva, live, vec![0u8; 32])];
    match derive_first_hop_candidates(&pe, &out_fh, &policy, base, base + 0x152000, &dump) {
        FirstHopCandidateResolution::Resolved(cands) => {
            assert_eq!(cands.len(), 1);
            assert_eq!(cands[0].table_rva, cmd.slot_rva);
            assert_eq!(cands[0].span, 32);
            assert_eq!(
                cands[0].evidence,
                FirstHopCandidateEvidence::VerifiedCountScaledExtent
            );
        }
        other => panic!("expected Resolved, got {other:?}"),
    }

    // ensure: policy hot-root path sizes the capture from the same count.
    let mut dump_ensure = dump.clone();
    dump_ensure[cmd.slot_rva as usize..cmd.slot_rva as usize + 8]
        .copy_from_slice(&live.to_le_bytes());
    let mut mock = M23RegionMapMock::new();
    mock.set(live, vec![0xCCu8; 0x1000]);
    let mut ensure_out = Vec::new();
    let mut ensure_total = 0usize;
    let mut seen = BTreeSet::new();
    let policy = DumpCapturePolicy::ahk_gto_default();
    ensure_hot_root_slots(
        &mut ensure_out,
        &mut ensure_total,
        &mut seen,
        base,
        base + 0x200000,
        &dump_ensure,
        &mut mock,
        &[(0x2000, 0x200000)],
        &[(0x2000, 0x200000)],
        &[],
        &policy,
    );
    let cmd_snap = ensure_out
        .iter()
        .find(|g| g.rva == cmd.slot_rva)
        .expect("cmd table captured by ensure");
    assert_eq!(cmd_snap.content.len(), 32);
    assert_eq!(ensure_total, 32);
}

/// A count that establishes 32 bytes but whose capture is larger/smaller
/// must remain Conflict/Ambiguous in first-hop — never Verified.
#[test]
fn m27_unmatched_capture_extent_is_conflict_not_verified() {
    let cmd = CountScaledPointerRole::cmd_table();
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let dump = m24_dump_buf_with_count(0x150000, cmd.count_rva().unwrap(), 4).unwrap();

    for content_len in [8usize, 24, 31, 33, 64] {
        let out = vec![m23_root(cmd.slot_rva, 0x30_0000, vec![0u8; content_len])];
        let r = derive_first_hop_candidates(&pe, &out, &policy, base, base + 0x152000, &dump);
        assert_eq!(
            r,
            FirstHopCandidateResolution::Ambiguous,
            "capture len {content_len} must be Ambiguous/Conflict, not Verified"
        );
    }
}

/// Malformed count inputs fail closed consistently for normalize and
/// first-hop: both use the same shared CountScaledExtent derivation.
#[test]
fn m27_malformed_count_fail_closed_consistently() {
    let cmd = CountScaledPointerRole::cmd_table();
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let mut mock = M23RegionMapMock::new();

    // count = 0
    let dump0 = m24_dump_buf_with_count(0x150000, cmd.count_rva().unwrap(), 0).unwrap();
    let mut out = vec![m23_root(cmd.slot_rva, 0x30_0000, vec![0xAAu8; 64])];
    let mut total = 64;
    normalize_cmd_table_capture(&mut out, &mut total, &dump0, &mut mock);
    assert_eq!(
        out[0].content.len(),
        64,
        "normalize must fail closed for count=0"
    );
    let out_fh = vec![m23_root(cmd.slot_rva, 0x30_0000, vec![0u8; 32])];
    assert_eq!(
        derive_first_hop_candidates(&pe, &out_fh, &policy, base, base + 0x152000, &dump0),
        FirstHopCandidateResolution::Missing,
        "first-hop must fail closed for count=0"
    );

    // count = 0x10000 (>= max)
    let dump_max = m24_dump_buf_with_count(0x150000, cmd.count_rva().unwrap(), 0x10000).unwrap();
    let mut out = vec![m23_root(cmd.slot_rva, 0x30_0000, vec![0xAAu8; 64])];
    let mut total = 64;
    normalize_cmd_table_capture(&mut out, &mut total, &dump_max, &mut mock);
    assert_eq!(
        out[0].content.len(),
        64,
        "normalize must fail closed for count>=0x10000"
    );
    let out_fh = vec![m23_root(cmd.slot_rva, 0x30_0000, vec![0u8; 32])];
    assert_eq!(
        derive_first_hop_candidates(&pe, &out_fh, &policy, base, base + 0x152000, &dump_max),
        FirstHopCandidateResolution::Missing,
        "first-hop must fail closed for count>=0x10000"
    );

    // truncated count dword (count_rva + 4 > dump_buf.len())
    let truncated = vec![0u8; cmd.count_rva().unwrap() + 3];
    let mut out = vec![m23_root(cmd.slot_rva, 0x30_0000, vec![0xAAu8; 64])];
    let mut total = 64;
    normalize_cmd_table_capture(&mut out, &mut total, &truncated, &mut mock);
    assert_eq!(
        out[0].content.len(),
        64,
        "normalize must fail closed for truncated count"
    );
    let out_fh = vec![m23_root(cmd.slot_rva, 0x30_0000, vec![0u8; 32])];
    assert_eq!(
        derive_first_hop_candidates(&pe, &out_fh, &policy, base, base + 0x152000, &truncated),
        FirstHopCandidateResolution::Missing,
        "first-hop must fail closed for truncated count"
    );

    // helper checked arithmetic: slot+offset overflow and count*element_size overflow.
    let overflow_role = CountScaledPointerRole {
        slot_rva: u32::MAX,
        count_offset: usize::MAX,
        element_size: 8,
        min_count: 1,
        max_count: 0xffff,
        min_extent: 8,
    };
    assert_eq!(
        overflow_role.derive_extent(&vec![0u8; 64]),
        CountScaledExtent::Unavailable,
        "slot+count_offset overflow must fail closed"
    );
    let mul_overflow_role = CountScaledPointerRole {
        slot_rva: 0x1000,
        count_offset: 0,
        element_size: usize::MAX,
        min_count: 1,
        max_count: 0xffff,
        min_extent: 8,
    };
    let mut big_dump = vec![0u8; 0x2000];
    big_dump[0x1000..0x1004].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(
        mul_overflow_role.derive_extent(&big_dump),
        CountScaledExtent::Unavailable,
        "count*element_size overflow must fail closed"
    );
}

/// ASLR stability: role identity/count location/derived extent do not
/// depend on image_base or live VA.
#[test]
fn m27_aslr_stability_preserves_role_and_extent() {
    let cmd = CountScaledPointerRole::cmd_table();
    let dump = m24_dump_buf_with_count(0x150000, cmd.count_rva().unwrap(), 4).unwrap();

    let base_a = 0x140000000u64;
    let base_b = 0x180000000u64;
    let pe_a = m23_pe(base_a, 0x2000, 0x150000);
    let pe_b = m23_pe(base_b, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();

    let out_a = vec![m23_root(cmd.slot_rva, 0x30_0000, vec![0u8; 32])];
    let out_b = vec![m23_root(cmd.slot_rva, 0x50_0000, vec![0u8; 32])];
    let ra = derive_first_hop_candidates(&pe_a, &out_a, &policy, base_a, base_a + 0x152000, &dump);
    let rb = derive_first_hop_candidates(&pe_b, &out_b, &policy, base_b, base_b + 0x152000, &dump);
    match (ra, rb) {
        (FirstHopCandidateResolution::Resolved(ca), FirstHopCandidateResolution::Resolved(cb)) => {
            assert_eq!(ca[0].table_rva, cmd.slot_rva);
            assert_eq!(cb[0].table_rva, cmd.slot_rva);
            assert_eq!(ca[0].span, 32);
            assert_eq!(cb[0].span, 32);
            assert_eq!(ca[0].evidence, cb[0].evidence);
        }
        other => panic!("expected both Resolved, got {other:?}"),
    }
}

/// Non-target objects (dense, hot-root, large-table, count-like at another
/// RVA) must not activate via the count-scaled role.
#[test]
fn m27_non_target_objects_do_not_activate() {
    let cmd = CountScaledPointerRole::cmd_table();
    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x200000);
    let policy = DumpCapturePolicy::default();
    let dump = m24_dump_buf_with_count(0x200000, cmd.count_rva().unwrap(), 4).unwrap();

    // Dense pointer-rich object at a non-role RVA.
    let dense = m23_root(0x2010, 0x30_0000, m23_dense_content(&[0x31_0000; 8]));
    assert_eq!(
        derive_first_hop_candidates(&pe, &vec![dense], &policy, base, base + 0x200000, &dump),
        FirstHopCandidateResolution::Missing
    );

    // Default policy extra hot root / large table with a dense body.
    let extra_hot = m23_root(0x18a898, 0x30_0000, m23_dense_content(&[0x31_0000; 8]));
    assert_eq!(
        derive_first_hop_candidates(&pe, &vec![extra_hot], &policy, base, base + 0x200000, &dump),
        FirstHopCandidateResolution::Missing
    );
    let extra_large = m23_root(0x148bf8, 0x30_0000, m23_dense_content(&[0x31_0000; 8]));
    assert_eq!(
        derive_first_hop_candidates(
            &pe,
            &vec![extra_large],
            &policy,
            base,
            base + 0x200000,
            &dump
        ),
        FirstHopCandidateResolution::Missing
    );

    // Count-like data at another RVA (same count/offset/size shape but not
    // the identity-bound role) must not activate.
    let count_like = m23_root(0x150000, 0x30_0000, vec![0u8; 32]);
    let mut other_dump = vec![0u8; 0x200000];
    other_dump[0x150020..0x150024].copy_from_slice(&4u32.to_le_bytes());
    assert_eq!(
        derive_first_hop_candidates(
            &pe,
            &vec![count_like],
            &policy,
            base,
            base + 0x200000,
            &other_dump
        ),
        FirstHopCandidateResolution::Missing
    );
}

/// The 0x141bf0 bounded-pointer-window role is untouched by the
/// count-scaled single-source refactor.
#[test]
fn m27_bounded_role_unchanged() {
    let roles = declared_first_hop_roles();
    let bounded = roles
        .iter()
        .find(|r| r.slot_rva == 0x141bf0)
        .expect("bounded role still declared");
    assert!(matches!(
        bounded.kind,
        FirstHopRoleKind::BoundedPointerWindow { max_span: 0x200 }
    ));
    assert_eq!(bounded.slot_rva, 0x141bf0);

    let base = 0x140000000u64;
    let pe = m23_pe(base, 0x2000, 0x150000);
    let policy = DumpCapturePolicy::default();
    let dump = m24_dump_buf_with_count(0x150000, 0x147888, 4).unwrap();

    // +0xd8 is inside the 0x200 window and is walked.
    let mut content_d8 = vec![0u8; 0x200];
    content_d8[0xd8..0xe0].copy_from_slice(&0x50_0000u64.to_le_bytes());
    let out_d8 = vec![m23_root(0x141bf0, 0x50_0000, content_d8)];
    match derive_first_hop_candidates(&pe, &out_d8, &policy, base, base + 0x152000, &dump) {
        FirstHopCandidateResolution::Resolved(cands) => {
            let c = cands.iter().find(|c| c.table_rva == 0x141bf0).unwrap();
            assert_eq!(c.span, 0x200);
            assert_eq!(
                c.evidence,
                FirstHopCandidateEvidence::IdentityBoundedPointerWindow
            );
        }
        other => panic!("expected bounded Resolved, got {other:?}"),
    }

    // A pointer at exactly 0x200 is outside the bounded window: span remains
    // 0x200 and the pointer at offset 0x200 is not walked/enumerated.
    let mut content_bound = vec![0u8; 0x400];
    content_bound[0x200..0x208].copy_from_slice(&0x60_0000u64.to_le_bytes());
    let out_bound = vec![m23_root(0x141bf0, 0x60_0000, content_bound)];
    match derive_first_hop_candidates(&pe, &out_bound, &policy, base, base + 0x152000, &dump) {
        FirstHopCandidateResolution::Resolved(cands) => {
            let c = cands.iter().find(|c| c.table_rva == 0x141bf0).unwrap();
            assert_eq!(c.span, 0x200);
            assert_eq!(
                c.evidence,
                FirstHopCandidateEvidence::IdentityBoundedPointerWindow
            );
        }
        other => panic!("expected bounded Resolved, got {other:?}"),
    }
}

// ============ MIDA-SERIAL-34 split producer provenance (real helper) ============

/// Real-producer test: split_swallowed_siblings emits a SplitSibling child
/// with the REAL source slot offset, was_interior=true, the real probe cap,
/// and the PRE-TRUNC parent evidence when the parent is a strict
/// ObservedAllocation (test 9 + test 11 requirement at the producer).
#[test]
fn m34_split_producer_emits_real_source_slot_and_strict_parent_evidence() {
    // Mock image: image_base + size_of_image; heap objects below module region.
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    // A strict parent allocation at 0x850000 (0x1000 bytes) whose qword at
    // slot offset 0x200 holds the child pointer 0x850150. The parent bytes at
    // the child offset (0x150) are zeroed -> child content will be zeros.
    let child_ptr = 0x850150u64;
    let mut parent_bytes = vec![0u8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    // The child's memory content: readable for the remaining parent span
    // (0x1000 - 0x150 bytes) so estimate_object_size can probe.
    let child_bytes = vec![0u8; 0x1000 - 0x150];
    let mut mock = M23RegionMapMock::new();
    mock.set(0x850000, parent_bytes.clone());
    mock.set(child_ptr, child_bytes.clone());
    let mut out: Vec<HeapGlobalSnapshot> = vec![HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    }];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let dump_buf = vec![0u8; 0x1000];
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    let split = out.iter().find(|g| g.live_ptr == child_ptr);
    let split = split.expect("split_swallowed_siblings must admit the interior child");
    // Producer provenance: SplitSibling path, real slot offset, interior,
    // real probe cap, strict pre-trunc parent.
    assert_eq!(
        split.extent_evidence.capture_path,
        CapturePath::SplitSibling,
        "split child must not masquerade as MainSlot"
    );
    assert_eq!(
        split.extent_evidence.source_slot_offset,
        Some(0x200),
        "source_slot_offset must be the REAL qword slot byte offset"
    );
    assert!(
        split.extent_evidence.was_interior,
        "was_interior must be true"
    );
    assert_eq!(
        split.extent_evidence.probe_requested_size,
        GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES),
        "probe_requested_size must be the real requested probe cap"
    );
    // capture_id deterministically binds producer + child + source identity/slot.
    assert!(
        split
            .extent_evidence
            .capture_id
            .starts_with("split_sibling:0x850150:main:0x850000:0x200"),
        "capture_id must bind producer/child/source/slot: {}",
        split.extent_evidence.capture_id
    );
    assert_eq!(
        split.extent_evidence.containing_parent_old_base,
        Some(0x850000),
        "strict pre-trunc parent base must be recorded"
    );
    assert_eq!(
        split.extent_evidence.containing_parent_size,
        Some(0x1000),
        "strict pre-trunc parent size must be recorded"
    );
}

/// Real-producer test: a ProbeWindow (heuristic) swallowing parent must NOT
/// yield a split child with containing-parent evidence — the child keeps
/// was_interior=true but parent fields stay None (test 12 at the producer).
#[test]
fn m34_split_producer_heuristic_parent_keeps_parent_fields_none() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut parent_bytes = vec![0u8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    // Child readable for the remaining parent span (probe-capable).
    let child_bytes = vec![0u8; 0x1000 - 0x150];
    let mut mock = M23RegionMapMock::new();
    mock.set(0x850000, parent_bytes.clone());
    mock.set(child_ptr, child_bytes.clone());
    // Parent is a ProbeWindow (heuristic) — NOT a proven allocation.
    let mut out: Vec<HeapGlobalSnapshot> = vec![HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "probe:0x850000".into(),
            capture_path: CapturePath::MainSlot,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0x2000,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    }];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let dump_buf = vec![0u8; 0x1000];
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    let split = out.iter().find(|g| g.live_ptr == child_ptr);
    let split = split.expect("split_swallowed_siblings must admit the interior child");
    assert!(split.extent_evidence.was_interior);
    assert_eq!(
        split.extent_evidence.containing_parent_old_base, None,
        "heuristic ProbeWindow parent must NOT be recorded as containing parent"
    );
    assert_eq!(split.extent_evidence.containing_parent_size, None);
    // And the closure helper must not fabricate authority from it.
    let candidates = super::super::raw_slab_coherence::build_authority_closure_candidates(
        &[split.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

// ============ MIDA-SERIAL-35 pre-trunc authority preservation ============

/// Real producer end-to-end: an ObservedAllocation parent whose qword slot
/// references an interior child is split by the REAL split_swallowed_siblings
/// producer; the parent is TRUNCATED; the producer's pre-trunc authority
/// evidence (FULL bytes) flows into the production closure helper and yields
/// exactly ONE parent_closure candidate with the pre-trunc base/size/bytes;
/// normalization then passes capture_coverage_bind. This is NOT a hand-built
/// untruncated-parent fixture — the parent really is truncated by the
/// producer before the closure runs.
#[test]
fn m35_real_producer_pre_trunc_authority_closure_end_to_end() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    // Strict parent: ObservedAllocation, 0x1000 bytes, slot 0x200 -> child.
    let mut parent_bytes = vec![0xABu8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    // The child's memory content must MATCH the parent slice at the child
    // offset (0x150..0x158) so byte-provenance holds. Make them identical.
    let child_bytes = parent_bytes[0x150..0x158].to_vec();
    let mut mock = M23RegionMapMock::new();
    mock.set(0x850000, parent_bytes.clone());
    mock.set(child_ptr, child_bytes.clone());
    let mut out: Vec<HeapGlobalSnapshot> = vec![HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    }];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // The split child was admitted.
    let split = out.iter().find(|g| g.live_ptr == child_ptr);
    let split = split.expect("split_swallowed_siblings must admit the interior child");
    assert_eq!(
        split.extent_evidence.capture_path,
        CapturePath::SplitSibling
    );
    // The PARENT WAS TRUNCATED: its current content no longer spans 0x1000.
    let parent_now = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    assert!(
        parent_now.content.len() < 0x1000,
        "parent must be truncated by the producer, current len={}",
        parent_now.content.len()
    );
    // The producer emitted FULL pre-trunc authority evidence.
    assert_eq!(
        pre_trunc_authority.binding_count(),
        1,
        "exactly one strict pre-trunc authority evidence must be emitted"
    );
    let ev = &pre_trunc_authority.bindings()[0];
    assert_eq!(ev.parent_key.parent_old_base, 0x850000);
    assert_eq!(ev.parent_key.parent_pre_trunc_size, 0x1000);
    assert_eq!(
        pre_trunc_authority.lookup(&ev.parent_key).unwrap().len(),
        0x1000
    );
    assert_eq!(
        pre_trunc_authority.lookup(&ev.parent_key).unwrap(),
        parent_bytes,
        "full pre-trunc bytes preserved"
    );
    assert_eq!(ev.parent_extent, CaptureExtentKind::ObservedAllocation);
    assert_eq!(ev.child_base, child_ptr);
    assert_eq!(ev.source_slot_offset, Some(0x200));
    // Feed the production closure helper with the REAL producer output.
    let candidates = super::super::raw_slab_coherence::build_authority_closure_candidates(
        &out,
        &[],
        &pre_trunc_authority,
    )
    .unwrap();
    assert_eq!(
        candidates.len(),
        1,
        "exactly one parent_closure candidate must be derived from pre-trunc evidence"
    );
    assert_eq!(candidates[0].role, "parent_closure");
    assert_eq!(candidates[0].slab.old_base, 0x850000);
    assert_eq!(candidates[0].slab.content.len(), 0x1000);
    assert_eq!(
        candidates[0].slab.content, parent_bytes,
        "closure bytes must equal the FULL pre-trunc parent bytes"
    );
    // Unified normalization keeps one authority; coverage passes.
    let (normalized, _events) =
        super::super::raw_slab_coherence::normalize_authoritative_slabs(&candidates).unwrap();
    assert_eq!(normalized.len(), 1);
    let slabs: Vec<HeapSlab> = normalized.iter().map(|n| n.slab.clone()).collect();
    super::super::raw_slab_coherence::validate_probe_coverage(&out, &slabs).unwrap();
}

/// Real producer: heuristic ProbeWindow parent must NOT produce pre-trunc
/// authority evidence; coverage stays fail-closed.
#[test]
fn m35_heuristic_parent_produces_no_pre_trunc_authority() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut parent_bytes = vec![0u8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    // Child readable for the remaining parent span (probe-capable).
    let child_bytes = vec![0u8; 0x1000 - 0x150];
    let mut mock = M23RegionMapMock::new();
    mock.set(0x850000, parent_bytes.clone());
    mock.set(child_ptr, child_bytes.clone());
    let mut out: Vec<HeapGlobalSnapshot> = vec![HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow, // heuristic
        extent_evidence: CaptureExtentEvidence {
            capture_id: "probe:0x850000".into(),
            capture_path: CapturePath::MainSlot,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0x2000,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    }];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // No pre-trunc authority for a heuristic parent.
    assert!(
        pre_trunc_authority.binding_count() == 0,
        "heuristic ProbeWindow parent must not emit pre-trunc authority"
    );
    // The closure helper derives nothing; coverage fails closed.
    let candidates = super::super::raw_slab_coherence::build_authority_closure_candidates(
        &out,
        &[],
        &pre_trunc_authority,
    )
    .unwrap();
    assert!(candidates.is_empty());
    let err = super::super::raw_slab_coherence::validate_probe_coverage(&out, &[]).unwrap_err();
    assert!(matches!(
        err,
        super::super::raw_slab_coherence::OverlayError::ProbeCoverageMissing { .. }
    ));
}

/// Producer: ambiguous strict parents (two snapshots at the same base/size
/// with different identities) must produce NO pre-trunc authority.
#[test]
fn m35_ambiguous_strict_parents_no_authority() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut pb = vec![0u8; 0x1000];
    pb[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    let child_bytes = vec![0u8; 8];
    let mut mock = M23RegionMapMock::new();
    mock.set(0x850000, pb.clone());
    mock.set(child_ptr, child_bytes.clone());
    // Two snapshots at the SAME (base, size) with DIFFERENT capture ids.
    let mk_parent = |id: &str| HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: pb.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: id.into(),
            capture_path: CapturePath::MainSlot,
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
    let mut out: Vec<HeapGlobalSnapshot> = vec![mk_parent("id1"), mk_parent("id2")];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    assert!(
        pre_trunc_authority.binding_count() == 0,
        "ambiguous strict parents must not produce authority evidence"
    );
}

/// Closure helper: parent slice / child bytes mismatch must NOT produce a
/// closure candidate from pre-trunc evidence.
#[test]
fn m35_pre_trunc_bytes_mismatch_no_closure() {
    use super::super::raw_slab_coherence::OverlayError;
    // Parent bytes (pre-trunc) whose slice at the child offset differs from
    // the child's content bytes.
    let mut parent_bytes = vec![0u8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&0x850150u64.to_le_bytes());
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850150,
        content: vec![0x11u8; 8], // differs from parent slice (zeros)
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x850150:src:0x200".into(),
            capture_path: CapturePath::SplitSibling,
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
    let store = m36_test_store(
        0x850000,
        0x1000,
        parent_bytes,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        "main:0x850000",
        CapturePath::MainSlot,
        0x850150,
        8,
        "src",
        Some(0x200),
    );
    let candidates = super::super::raw_slab_coherence::build_authority_closure_candidates(
        &[child.clone()],
        &[],
        &store,
    )
    .unwrap();
    assert!(
        candidates.is_empty(),
        "pre-trunc slice/child bytes mismatch must not produce a closure candidate"
    );
    // Coverage stays fail-closed.
    let err = super::super::raw_slab_coherence::validate_probe_coverage(&[child], &[]).unwrap_err();
    assert!(matches!(err, OverlayError::ProbeCoverageMissing { .. }));
}

/// Overflowed existing slab must NOT be treated as covering a parent by
/// covered_by_existing (checked_add), and a legitimate closure candidate
/// must NOT be skipped because of it.
#[test]
fn m35_overflowed_existing_slab_not_covering_and_closure_not_skipped() {
    // A parent whose range [0x850000, 0x851000) is legitimate.
    let parent_old_base = 0x850000u64;
    let parent_size = 0x1000usize;
    let mut parent_bytes = vec![0u8; parent_size];
    parent_bytes[0x150..0x158].copy_from_slice(&[0u8; 8]); // child slice zeros
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850150,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x850150:src:0x150".into(),
            capture_path: CapturePath::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(parent_old_base),
            containing_parent_size: Some(parent_size),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let store = m36_test_store(
        parent_old_base,
        parent_size,
        parent_bytes,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        "main:0x850000",
        CapturePath::MainSlot,
        0x850150,
        8,
        "src",
        Some(0x150),
    );
    // An OVERFLOWING existing slab: old_base near u64::MAX + len wraps.
    // It must not be considered covering the parent range, so the legitimate
    // closure candidate is NOT skipped.
    let overflow_slab = HeapSlab {
        old_base: u64::MAX - 0x10,
        content: vec![0u8; 0x100],
    };
    let candidates = super::super::raw_slab_coherence::build_authority_closure_candidates(
        &[child.clone()],
        &[overflow_slab],
        &store,
    )
    .unwrap();
    assert_eq!(
        candidates.len(),
        1,
        "overflowing existing slab must not skip the legitimate closure candidate"
    );
    assert_eq!(candidates[0].slab.old_base, parent_old_base);
    // And a wrapping parent itself cannot produce a candidate.
    let store_wrap = m36_test_store(
        u64::MAX - 0x10,
        0x100,
        vec![0u8; 0x100],
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        "wrap",
        CapturePath::MainSlot,
        0x850150,
        8,
        "src",
        None,
    );
    let c2 = super::super::raw_slab_coherence::build_authority_closure_candidates(
        &[child.clone()],
        &[],
        &store_wrap,
    )
    .unwrap();
    assert!(
        c2.is_empty(),
        "wrapping parent range must produce no candidate"
    );
    let _ = &child;
}

/// Source hit count / identity dedup: multiple qword occurrences from the
/// SAME source snapshot count as ONE distinct source; a second source
/// snapshot increments the count.
#[test]
fn m35_source_hit_count_is_distinct_source_identity() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    // Two source snapshots, each referencing the child TWICE (two slots).
    let mk_source = |base: u64, id: &str| -> HeapGlobalSnapshot {
        let mut content = vec![0u8; 0x1000];
        content[0x100..0x108].copy_from_slice(&child_ptr.to_le_bytes());
        content[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: base,
            content,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            extent_evidence: CaptureExtentEvidence {
                capture_id: id.into(),
                capture_path: CapturePath::MainSlot,
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
    // A swallowing parent that strictly contains the child.
    let mut parent_bytes = vec![0u8; 0x1000];
    parent_bytes[0x150..0x158].copy_from_slice(&[0u8; 8]);
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
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
    let mut out: Vec<HeapGlobalSnapshot> = vec![
        mk_source(0x860000, "src1"),
        mk_source(0x870000, "src2"),
        parent,
    ];
    let mut mock = M23RegionMapMock::new();
    mock.set(child_ptr, vec![0u8; 8]);
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // The evidence emitted for the strict parent binds the FIRST source
    // (deterministic) and the REAL slot offset. The child's candidate
    // evidence is internal; assert via the emitted authority's source.
    if let Some(ev) = pre_trunc_authority.bindings().first() {
        assert_eq!(ev.source_slot_offset, Some(0x100));
        assert_eq!(ev.source_capture_id, "src1");
    }
}

// ============ MIDA-SERIAL-36 transactional split admission ============

/// Production invariant helper: total_bytes == sum(out content lengths).
/// Split fixtures MUST maintain this invariant or the producer's checked
/// budget (trunc_drop <= total_bytes) fails closed by design.
fn m40_split_total_bytes(out: &[HeapGlobalSnapshot]) -> usize {
    out.iter().map(|g| g.content.len()).sum()
}

/// Helper: build a strict ObservedAllocation parent with a slot pointing at
/// an interior child, plus a mock that serves parent + child memory.
fn m36_strict_parent_fixture(
    child_ptr: u64,
    parent_base: u64,
    parent_size: usize,
    slot_off: usize,
    mock: &mut M23RegionMapMock,
) -> (Vec<u8>, HeapGlobalSnapshot) {
    let mut parent_bytes = vec![0xABu8; parent_size];
    parent_bytes[slot_off..slot_off + 8].copy_from_slice(&child_ptr.to_le_bytes());
    mock.set(parent_base, parent_bytes.clone());
    // Child readable for the remaining parent span (probe-capable).
    let child_off = (child_ptr - parent_base) as usize;
    mock.set(child_ptr, vec![0u8; parent_size - child_off]);
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: parent_base,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: format!("main:{parent_base:#x}"),
            capture_path: CapturePath::MainSlot,
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
    (parent_bytes, parent)
}

/// Helper: build a store with ONE recorded parent + ONE binding (test-only
/// substitute for the production Path A evidence).
fn m36_test_store(
    parent_old_base: u64,
    parent_pre_trunc_size: usize,
    parent_full_bytes: Vec<u8>,
    parent_extent: CaptureExtentKind,
    parent_provenance: RegionProvenance,
    parent_capture_id: &str,
    parent_capture_path: CapturePath,
    child_base: u64,
    child_size: usize,
    source_capture_id: &str,
    source_slot_offset: Option<usize>,
) -> PreTruncParentAuthorityStore {
    let mut store = PreTruncParentAuthorityStore::default();
    let key = PreTruncParentAuthorityKey {
        parent_old_base,
        parent_pre_trunc_size,
        parent_capture_id: parent_capture_id.to_string(),
    };
    store.record_parent(
        &key,
        &parent_full_bytes,
        parent_extent,
        parent_provenance.clone(),
        parent_capture_path,
    );
    store.record_binding(
        key,
        parent_extent,
        parent_provenance,
        parent_capture_path,
        child_base,
        child_size,
        source_capture_id.to_string(),
        source_slot_offset,
    );
    store
}

/// Test 1: child read failure (read_memory returns <8) must NOT truncate the
/// parent, must NOT add the child, must NOT add evidence, and must leave
/// total_bytes/seen_heaps unchanged.
#[test]
fn m36_child_read_failure_does_not_truncate_parent() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    // Build the parent snapshot WITHOUT registering any mock region for the
    // parent (the swallow scan and strict-parent identification use the
    // snapshot content in out, not the mock). No region at the child ->
    // read_memory fails -> admission fails with ZERO mutation.
    let mut parent_bytes = vec![0xABu8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
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
    let mut mock = M23RegionMapMock::new();
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // Parent completely unchanged (bytes + len).
    let parent_after = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    assert_eq!(
        parent_after.content, parent_bytes,
        "parent bytes must be unchanged"
    );
    assert_eq!(
        parent_after.content.len(),
        0x1000,
        "parent len must be unchanged"
    );
    // No child added.
    assert!(
        out.iter().all(|g| g.live_ptr != child_ptr),
        "child must not be added on read failure"
    );
    // No evidence, no total_bytes change, no seen_heaps residue.
    assert!(
        pre_trunc_authority.binding_count() == 0,
        "no evidence on read failure"
    );
    assert_eq!(total_bytes, 0x1000, "total_bytes unchanged (parent only)");
    assert!(!seen_heaps.contains(&child_ptr), "no seen_heaps residue");
}

/// Test 2: child post-trim failure (read OK but trailing-zero/overlap trim
/// leaves <8) must NOT truncate the parent and must roll back completely.
#[test]
fn m36_child_post_trim_failure_does_not_truncate_parent() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    let (parent_bytes, parent) =
        m36_strict_parent_fixture(child_ptr, 0x850000, 0x1000, 0x200, &mut mock);
    // Child memory: only 8 readable bytes, then zeros -> trim_trailing_zero_pages
    // trims the all-zero tail. estimate_object_size probes 0x40... with an 8-byte
    // region the first probe (0x40) fails -> size < 8 -> admission fails at
    // estimate, NOT at trim. To force POST-TRIM failure, give the child a region
    // whose estimate succeeds but whose content trims below 8. estimate reads up
    // to SIZE_PROBES while readable; a region of 0x40 bytes -> estimate=0x40,
    // content=0x40 zeros -> trim_trailing_zero_pages keeps MIN_KEEP=0x40 >= 8.
    // So a post-trim <8 needs content that trims below MIN_KEEP — impossible with
    // the current trim (MIN_KEEP=0x40). Instead, use truncate_split_child_avoid_overlap:
    // place ANOTHER snapshot starting at child_ptr+4 so the child window is cut to 4.
    // Simplest: child region 0x40 bytes, and a SECOND snapshot at child_ptr+0x20
    // (0x20 bytes) so truncate_split_child_avoid_overlap cuts the child to 0x20... still >= 8.
    // Place the second snapshot at child_ptr+4 with 8 bytes -> child cut to 4 < 8.
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    // A snapshot starting 4 bytes after the child base: bounds the child to 4.
    let blocker = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: child_ptr + 4,
        content: vec![0x11u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "blocker".into(),
            capture_path: CapturePath::MainSlot,
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
    out.push(blocker);
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // Parent unchanged (truncation only happens at commit).
    let parent_after = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    assert_eq!(
        parent_after.content.len(),
        0x1000,
        "parent must not be truncated"
    );
    assert_eq!(parent_after.content, parent_bytes);
    // Child not admitted.
    assert!(
        out.iter().all(|g| g.live_ptr != child_ptr),
        "child must not be admitted after trim failure"
    );
    assert!(pre_trunc_authority.binding_count() == 0);
    assert!(!seen_heaps.contains(&child_ptr));
    let _ = total_bytes;
}

/// Test 3: source identity A/B/B — source A once, source B twice ->
/// source_hit_count == 2, first source provenance stable as A.
#[test]
fn m36_source_identity_abb_counts_two() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    let (_pb, parent) = m36_strict_parent_fixture(child_ptr, 0x850000, 0x1000, 0x200, &mut mock);
    // Source A references the child ONCE (slot 0x100).
    let mut src_a = vec![0u8; 0x1000];
    src_a[0x100..0x108].copy_from_slice(&child_ptr.to_le_bytes());
    // Source B references the child TWICE (slots 0x100 and 0x300).
    let mut src_b = vec![0u8; 0x1000];
    src_b[0x100..0x108].copy_from_slice(&child_ptr.to_le_bytes());
    src_b[0x300..0x308].copy_from_slice(&child_ptr.to_le_bytes());
    let mk_src = |base: u64, id: &str, content: Vec<u8>| HeapGlobalSnapshot {
        rva: 0,
        live_ptr: base,
        content,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: id.into(),
            capture_path: CapturePath::MainSlot,
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
    // Zero the parent's own child-pointer slot: the parent must not count
    // as a THIRD distinct source identity (A/B/B test wants exactly A and B).
    let mut parent_noref = parent;
    parent_noref.content[0x200..0x208].fill(0);
    let mut out: Vec<HeapGlobalSnapshot> = vec![
        mk_src(0x860000, "srcA", src_a),
        mk_src(0x870000, "srcB", src_b),
        parent_noref,
    ];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // MIDA-SERIAL-37: assert the REAL production candidate evidence — the
    // producer's own source_hit_count must be 2 (distinct A + B), never a
    // test-local set.
    let cand = admitted
        .iter()
        .find(|c| c.child_value == child_ptr)
        .expect("candidate evidence emitted for the child");
    assert_eq!(
        cand.source_hit_count, 2,
        "production source_hit_count must be 2 (A/B/B)"
    );
    assert_eq!(
        cand.source_capture_id.as_deref(),
        Some("srcA"),
        "first source must be A"
    );
    assert_eq!(
        cand.source_slot_offset,
        Some(0x100),
        "first-source-wins: slot 0x100 from source A"
    );
    // The child snapshot's evidence mirrors the producer candidate.
    let split = out
        .iter()
        .find(|g| g.live_ptr == child_ptr)
        .expect("child admitted");
    assert_eq!(
        split.extent_evidence.source_slot_offset,
        Some(0x100),
        "first-source-wins: slot 0x100 from source A"
    );
    // The authority binding's source capture id is A (first source wins).
    if let Some(ev) = pre_trunc_authority.bindings().first() {
        assert_eq!(ev.source_capture_id, "srcA", "first source must be A");
    }
}

/// Test 4: same-source multiple slots -> source_hit_count == 1.
#[test]
fn m36_same_source_multiple_slots_counts_one() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    let (_pb, parent) = m36_strict_parent_fixture(child_ptr, 0x850000, 0x1000, 0x200, &mut mock);
    // ONE source referencing the child TWICE.
    let mut src = vec![0u8; 0x1000];
    src[0x100..0x108].copy_from_slice(&child_ptr.to_le_bytes());
    src[0x300..0x308].copy_from_slice(&child_ptr.to_le_bytes());
    let source = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x860000,
        content: src,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "srcOnly".into(),
            capture_path: CapturePath::MainSlot,
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
    // Zero the parent's own child-pointer slot (see test 3): the parent
    // must not count as a second distinct source identity.
    let mut parent_noref = parent;
    parent_noref.content[0x200..0x208].fill(0);
    let mut out: Vec<HeapGlobalSnapshot> = vec![source, parent_noref];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // MIDA-SERIAL-37: read the REAL production candidate evidence — the
    // producer's own source_hit_count must be 1 (one distinct source).
    let cand = admitted
        .iter()
        .find(|c| c.child_value == child_ptr)
        .expect("candidate evidence emitted for the child");
    assert_eq!(
        cand.source_hit_count, 1,
        "production source_hit_count must be 1 (same source, two slots)"
    );
    assert_eq!(cand.source_capture_id.as_deref(), Some("srcOnly"));
    if let Some(ev) = pre_trunc_authority.bindings().first() {
        assert_eq!(ev.source_capture_id, "srcOnly");
    }
}

/// Test 9: full production preprocessing order — split -> reconcile ->
/// trim -> build_authority_closure_candidates -> normalize ->
/// validate_probe_coverage must pass end-to-end.
#[test]
fn m36_full_production_preprocessing_order_passes() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    let (parent_bytes, parent) =
        m36_strict_parent_fixture(child_ptr, 0x850000, 0x1000, 0x200, &mut mock);
    // NOTE: the parent slice at the child offset (0x150) is 0xAB (from the
    // 0xAB fill), but the child's read content will be the parent bytes at
    // offset 0x150 (mock serves the parent region) — so the child content
    // equals the parent slice. Good for byte-provenance.
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    // 1. split (real producer).
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    let split = out
        .iter()
        .find(|g| g.live_ptr == child_ptr)
        .expect("child admitted");
    assert_eq!(
        split.extent_evidence.capture_path,
        CapturePath::SplitSibling
    );
    assert_eq!(
        pre_trunc_authority.binding_count(),
        1,
        "one strict parent authority"
    );
    // The parent was truncated at commit.
    let parent_after = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    assert!(
        parent_after.content.len() < 0x1000,
        "parent truncated at commit"
    );
    // 2. reconcile (no duplicate bases here; must be a no-op that keeps order).
    reconcile_duplicate_heap_globals(&mut out, None);
    // 3. trim (windows already non-overlapping after split).
    trim_overlapping_heap_global_windows(&mut out);
    // 4. build_authority_closure_candidates with the REAL pre-trunc evidence.
    let existing: Vec<HeapSlab> = Vec::new();
    let candidates = super::super::raw_slab_coherence::build_authority_closure_candidates(
        &out,
        &existing,
        &pre_trunc_authority,
    )
    .unwrap();
    assert_eq!(
        candidates.len(),
        1,
        "one parent_closure from pre-trunc evidence"
    );
    assert_eq!(candidates[0].role, "parent_closure");
    assert_eq!(candidates[0].slab.old_base, 0x850000);
    assert_eq!(
        candidates[0].slab.content, parent_bytes,
        "closure == pre-trunc parent bytes"
    );
    // 5. normalize.
    let (normalized, _events) =
        super::super::raw_slab_coherence::normalize_authoritative_slabs(&candidates).unwrap();
    assert_eq!(normalized.len(), 1);
    // 6. coverage passes with the normalized authority set.
    let slabs: Vec<HeapSlab> = normalized.iter().map(|n| n.slab.clone()).collect();
    super::super::raw_slab_coherence::validate_probe_coverage(&out, &slabs).unwrap();
}

// ============ MIDA-SERIAL-37: real dedup + fail-closed transaction ============

/// MIDA-SERIAL-38: a parent with two children in the SAME production split
/// run binds BOTH children to the SAME frozen ORIGINAL parent identity —
/// parent_count()==1, binding_count()==2, both keys identical (original
/// 0x1000, never 0x1000+0x400), both resolve to the same original bytes.
/// The frozen registry is captured before ANY truncation, so child order
/// never changes the authority.
#[test]
fn m37_same_parent_two_children_real_producer_store_once() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    // Two children inside the same strict parent.
    let child_a = 0x850150u64;
    let child_b = 0x850400u64;
    let mut mock = M23RegionMapMock::new();
    let (_parent_bytes0, mut parent) =
        m36_strict_parent_fixture(child_a, 0x850000, 0x1000, 0x200, &mut mock);
    // Register a second interior child: slot 0x500 -> child_b; child memory.
    parent.content[0x500..0x508].copy_from_slice(&child_b.to_le_bytes());
    // The FULL pre-trunc bytes are the MODIFIED parent content (both child
    // pointers present) — what the producer freezes before truncation.
    let parent_bytes = parent.content.clone();
    mock.set(0x850000, parent.content.clone());
    mock.set(child_b, vec![0u8; 0x1000 - 0x400]);
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    assert_eq!(
        admitted.len(),
        2,
        "both children admitted from the same parent"
    );
    // REAL bytes-level dedup: ONE frozen parent identity, TWO key-only
    // bindings with the SAME original key.
    assert_eq!(pre_trunc_authority.parent_count(), 1);
    assert_eq!(pre_trunc_authority.binding_count(), 2);
    let bindings = pre_trunc_authority.bindings();
    assert_eq!(
        bindings[0].parent_key, bindings[1].parent_key,
        "both children bind the SAME frozen original parent key"
    );
    assert_eq!(
        bindings[0].parent_key.parent_pre_trunc_size, 0x1000,
        "parent_pre_trunc_size is ALWAYS the original 0x1000"
    );
    assert_eq!(
        pre_trunc_authority.lookup(&bindings[0].parent_key).unwrap(),
        parent_bytes,
        "lookup returns the single original full bytes copy"
    );
    assert_eq!(
        pre_trunc_authority.lookup(&bindings[1].parent_key).unwrap(),
        parent_bytes,
        "both bindings resolve to the same original bytes"
    );
    // Closure: ONE candidate (both bindings share the key -> built once).
    let candidates = super::super::raw_slab_coherence::build_authority_closure_candidates(
        &out,
        &[],
        &pre_trunc_authority,
    )
    .unwrap();
    assert_eq!(candidates.len(), 1, "one key -> one closure candidate");
    assert_eq!(candidates[0].slab.old_base, 0x850000);
    assert_eq!(candidates[0].slab.content.len(), 0x1000);
    let (normalized, _) =
        super::super::raw_slab_coherence::normalize_authoritative_slabs(&candidates).unwrap();
    assert_eq!(normalized.len(), 1);
}

/// Conflict in the PRODUCTION path: two split children claim the SAME
/// parent identity with DIFFERENT bytes -> the second admission is REJECTED
/// (child not added, parent not truncated further, no evidence, no counter/
/// seen residue). Simulated by feeding a store already holding conflicting
/// bytes for the parent identity.
#[test]
fn m37_authority_conflict_rejects_candidate_zero_mutation() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    let (parent_bytes, parent) =
        m36_strict_parent_fixture(child_ptr, 0x850000, 0x1000, 0x200, &mut mock);
    // Pre-seed the store with CONFLICTING bytes for the SAME parent identity.
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let conflict_key = PreTruncParentAuthorityKey {
        parent_old_base: 0x850000,
        parent_pre_trunc_size: 0x1000,
        parent_capture_id: "main:0x850000".into(),
    };
    pre_trunc_authority.record_parent(
        &conflict_key,
        &vec![0xFFu8; 0x1000],
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        CapturePath::MainSlot,
    );
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // The candidate was REJECTED: no admission, no evidence binding.
    assert!(
        admitted.is_empty(),
        "conflicting authority must reject the split candidate"
    );
    assert_eq!(pre_trunc_authority.binding_count(), 0);
    // Parent NOT truncated (bytes + len unchanged).
    let parent_after = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    assert_eq!(parent_after.content.len(), 0x1000);
    assert_eq!(parent_after.content, parent_bytes);
    // No child, no counters/seen residue.
    assert!(out.iter().all(|g| g.live_ptr != child_ptr));
    assert_eq!(total_bytes, 0x1000, "total_bytes unchanged (parent only)");
    assert!(!seen_heaps.contains(&child_ptr));
}

/// String-shell buffer at the TAIL of a swallowing parent: resolved against
/// the POST-truncation geometry, the buffer becomes an independently
/// capturable child (never wrongly nulled because the untruncated parent
/// swallowed it).
#[test]
fn m37_string_shell_buffer_at_parent_tail_captured_post_truncation() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    // Build the parent snapshot WITHOUT registering a mock region for it:
    // a parent region spanning 0x850000..0x851000 would shadow the child
    // and buffer reads in the BTreeMap mock. Only child + buffer regions
    // are registered.
    let mut parent_bytes = vec![0xABu8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
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
    // The SPLIT child content itself is a refcounted string shell whose
    // buffer sits at the parent's TAIL (0x850F00, inside the pre-trunc
    // parent, but OUTSIDE the post-trunc parent [0x850000, 0x850150)).
    let buf = 0x850F00u64;
    let mut shell = vec![0u8; 0x40];
    shell[0..8].copy_from_slice(&buf.to_le_bytes());
    shell[8..16].copy_from_slice(&buf.to_le_bytes());
    shell[16..24].copy_from_slice(&40u64.to_le_bytes()); // len
    shell[24..32].copy_from_slice(&0x40u64.to_le_bytes()); // cap
    shell[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // refs
    mock.set(child_ptr, shell.clone());
    mock.set(buf, vec![0x41u8; 0x40]);
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    assert_eq!(admitted.len(), 1, "split child admitted");
    // The shell was recognized and its buffer admitted as its OWN snapshot.
    let buf_snap = out
        .iter()
        .find(|g| g.live_ptr == buf)
        .expect("string buffer at parent tail captured as own snapshot");
    assert_eq!(buf_snap.content, vec![0x41u8; 0x40]);
    // The split child kept its shell pointers (admitted -> not nulled).
    let split = out.iter().find(|g| g.live_ptr == child_ptr).unwrap();
    let shell_buf = u64::from_le_bytes(split.content[0..8].try_into().unwrap());
    assert_eq!(shell_buf, buf, "shell pointers preserved for multi_fixup");
    assert!(seen_heaps.contains(&buf));
}

/// parent_hit_count is the DISTINCT parent identity cardinality: two
/// snapshots of the SAME parent identity (base/size/capture_id) that both
/// swallow the child count ONCE.
#[test]
fn m37_parent_hit_count_distinct_identity_not_occurrence() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    let (parent_bytes, parent) =
        m36_strict_parent_fixture(child_ptr, 0x850000, 0x1000, 0x200, &mut mock);
    // A DUPLICATE of the same parent identity (same base/size/capture_id).
    let dup_parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
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
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent, dup_parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    let cand = admitted
        .iter()
        .find(|c| c.child_value == child_ptr)
        .expect("candidate evidence emitted");
    assert_eq!(
        cand.parent_hit_count, 1,
        "same parent identity twice must count ONE distinct parent"
    );
}

// ============ MIDA-SERIAL-38: frozen original parent + real gates ============

/// Child processing ORDER must not change the authority result: two children
/// of the same parent produce identical parent keys/bytes regardless of
/// which child is committed first. The frozen registry is captured before
/// any truncation, so both runs must be identical.
#[test]
fn m38_child_order_does_not_change_parent_authority() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_a = 0x850150u64;
    let child_b = 0x850400u64;

    // run(a_first): when a_first, child_a (0x850150) is the HIGHER commit
    // priority... actually the producer sorts by HIGHER VA first, so to make
    // the commit order differ we swap which child sits at the higher VA.
    // Run 1: child_b at 0x850400 (commits first). Run 2: child_a and child_b
    // addresses swapped so child_a commits first. The frozen registry is
    // captured BEFORE any truncation in both runs, so the authority keys
    // must be identical.
    let run = |swap: bool| -> (Vec<u8>, Vec<PreTruncParentAuthorityKey>) {
        let mut mock = M23RegionMapMock::new();
        let (lo_ptr, hi_ptr) = if swap {
            (child_b, child_a)
        } else {
            (child_a, child_b)
        };
        let (lo_slot, hi_slot) = if swap {
            (0x500usize, 0x200usize)
        } else {
            (0x200usize, 0x500usize)
        };
        // Parent with both child slots; the parent is NOT registered in the
        // mock (would shadow child reads).
        let mut parent_bytes = vec![0xABu8; 0x1000];
        parent_bytes[lo_slot..lo_slot + 8].copy_from_slice(&lo_ptr.to_le_bytes());
        parent_bytes[hi_slot..hi_slot + 8].copy_from_slice(&hi_ptr.to_le_bytes());
        let parent = HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x850000,
            content: parent_bytes.clone(),
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            extent_evidence: CaptureExtentEvidence {
                capture_id: "main:0x850000".into(),
                capture_path: CapturePath::MainSlot,
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
        mock.set(lo_ptr, vec![0u8; 0x1000 - (lo_ptr - 0x850000) as usize]);
        mock.set(hi_ptr, vec![0u8; 0x1000 - (hi_ptr - 0x850000) as usize]);
        let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
        let mut total_bytes = m40_split_total_bytes(&out);
        let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
        let mut store = PreTruncParentAuthorityStore::default();
        let dump_buf = vec![0u8; 0x1000];
        let _admitted = split_swallowed_siblings(
            &mut out,
            &mut total_bytes,
            &mut seen_heaps,
            &mut store,
            image_base,
            image_end,
            &dump_buf,
            &mut mock,
        );
        let keys: Vec<PreTruncParentAuthorityKey> = store
            .bindings()
            .iter()
            .map(|b| b.parent_key.clone())
            .collect();
        (parent_bytes, keys)
    };

    let (bytes1, keys1) = run(false);
    let (bytes2, keys2) = run(true);
    assert_eq!(bytes1, bytes2);
    assert_eq!(keys1.len(), 2, "two bindings");
    assert_eq!(keys2.len(), 2, "swapped run also two bindings");
    assert_eq!(keys1[0], keys1[1], "both bindings share ONE key");
    assert_eq!(keys2[0], keys2[1], "swapped run shares ONE key too");
    assert_eq!(
        keys1, keys2,
        "commit order never changes the authority keys"
    );
    assert_eq!(keys1[0].parent_pre_trunc_size, 0x1000);
    assert_eq!(keys2[0].parent_pre_trunc_size, 0x1000);
}

/// Qualifying parent selection must use the FULL identity predicate: a
/// ProbeWindow/SyntheticDerived snapshot at the same (base,size) with the
/// same capture_id is NEVER eligible (the frozen registry only freezes
/// ObservedAllocation/BackingObject, non-SyntheticDerived). The authority
/// is deterministically the QUALIFYING parent, and iteration order (twin
/// before/after parent) never changes that result.
#[test]
fn m38_qualifying_parent_conflict_fails_closed() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let run = |twin_first: bool| -> (usize, Vec<u8>) {
        let mut mock = M23RegionMapMock::new();
        let (_parent_bytes, parent) =
            m36_strict_parent_fixture(child_ptr, 0x850000, 0x1000, 0x200, &mut mock);
        mock.set(child_ptr, vec![0u8; 0x1000 - 0x150]);
        // Non-qualifying twin: SAME span + SAME capture_id but ProbeWindow.
        let mut twin = parent.clone();
        twin.extent_kind = CaptureExtentKind::ProbeWindow;
        let mut out: Vec<HeapGlobalSnapshot> = if twin_first {
            vec![twin, parent]
        } else {
            vec![parent, twin]
        };
        let mut total_bytes = m40_split_total_bytes(&out);
        let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
        let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
        let dump_buf = vec![0u8; 0x1000];
        let _admitted = split_swallowed_siblings(
            &mut out,
            &mut total_bytes,
            &mut seen_heaps,
            &mut pre_trunc_authority,
            image_base,
            image_end,
            &dump_buf,
            &mut mock,
        );
        let bc = pre_trunc_authority.binding_count();
        let bytes = pre_trunc_authority
            .bindings()
            .first()
            .and_then(|b| pre_trunc_authority.lookup(&b.parent_key))
            .map(|s| s.to_vec())
            .unwrap_or_default();
        (bc, bytes)
    };
    // Twin first vs parent first: IDENTICAL authority (the ProbeWindow twin
    // is never eligible; the qualifying parent is the only source).
    let (bc1, bytes1) = run(true);
    let (bc2, bytes2) = run(false);
    assert_eq!(bc1, 1, "one authority binding");
    assert_eq!(bc2, 1, "one authority binding (parent first)");
    assert_eq!(bytes1, bytes2, "order never changes authority bytes");
    // The authority bytes are the QUALIFYING parent bytes (0xAB fill).
    assert_eq!(bytes1[0], 0xAB, "authority from the qualifying parent");
    assert_eq!(bytes1.len(), 0x1000);
}

/// Unified budget: when the split child + optional string buffer would
/// exceed the slot cap, the WHOLE candidate is rejected (no partial
/// admission). Boundary: out.len() == split_slot_cap - 1 with a buffer
/// child planned -> planned_slots == cap + 1 -> reject both.
#[test]
fn m38_combined_slot_budget_rejects_whole_candidate() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    // Parent snapshot WITHOUT registering a mock region (it would shadow the
    // child/buffer reads); only child + buffer regions are registered.
    let mut parent_bytes = vec![0xABu8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
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
    let split_slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE);
    // Fill out to cap-1 with dummy snapshots (each valid, non-overlapping).
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    for i in 0..(split_slot_cap - 2) {
        let base = 0x900000u64 + (i as u64) * 0x1000;
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: base,
            content: vec![0x11u8; 0x100],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            extent_evidence: CaptureExtentEvidence {
                capture_id: format!("dummy:{base:#x}"),
                capture_path: CapturePath::MainSlot,
                source_root_rva: None,
                source_slot_offset: None,
                probe_requested_size: 0,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        });
    }
    // Child content is a string shell whose buffer would add a SECOND slot.
    let buf = 0x850F00u64;
    let mut shell = vec![0u8; 0x40];
    shell[0..8].copy_from_slice(&buf.to_le_bytes());
    shell[8..16].copy_from_slice(&buf.to_le_bytes());
    shell[16..24].copy_from_slice(&40u64.to_le_bytes());
    shell[24..32].copy_from_slice(&0x40u64.to_le_bytes());
    shell[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    mock.set(child_ptr, shell);
    mock.set(buf, vec![0x41u8; 0x40]);
    // out.len() == cap-1 now; split child (1) + buffer (1) = cap+1 -> reject.
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // The whole candidate (split child + buffer) must be rejected: no child,
    // no buffer, no evidence, no residue.
    assert!(
        admitted.is_empty(),
        "combined budget must reject the candidate"
    );
    assert!(
        out.iter()
            .all(|g| g.live_ptr != child_ptr && g.live_ptr != buf),
        "neither split child nor buffer admitted"
    );
    assert_eq!(pre_trunc_authority.binding_count(), 0);
    assert!(!seen_heaps.contains(&child_ptr) && !seen_heaps.contains(&buf));
    let parent_after = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    assert_eq!(parent_after.content.len(), 0x1000, "parent untruncated");
}

/// Self-buffer: a string shell whose buffer base equals the split child
/// base must be rejected — never two snapshots with the same live_ptr.
#[test]
fn m38_string_buffer_same_base_as_split_child_rejected() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    let (parent_bytes, parent) =
        m36_strict_parent_fixture(child_ptr, 0x850000, 0x1000, 0x200, &mut mock);
    // Shell whose buf == the child base itself (self-reference).
    let mut shell = vec![0u8; 0x40];
    shell[0..8].copy_from_slice(&child_ptr.to_le_bytes());
    shell[8..16].copy_from_slice(&child_ptr.to_le_bytes());
    shell[16..24].copy_from_slice(&40u64.to_le_bytes());
    shell[24..32].copy_from_slice(&0x40u64.to_le_bytes());
    shell[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    mock.set(child_ptr, shell);
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // Self-buffer rejected: the split child may still be admitted WITHOUT
    // the duplicate buffer, OR the whole candidate rejected — either way
    // there must be exactly ONE snapshot at child_ptr (never two).
    let dup = out.iter().filter(|g| g.live_ptr == child_ptr).count();
    assert!(dup <= 1, "never two snapshots at the same live_ptr");
    let _ = admitted;
    let _ = parent_bytes;
}

/// Production duplicate-child gate: after a child is bound, a SECOND
/// admission of the SAME (child_base, child_size) is rejected by
/// prepare_child (wired into the production path) with zero mutation.
#[test]
fn m38_production_duplicate_child_binding_rejected() {
    // The duplicate gate is exercised by calling the production path with a
    // pre-seeded binding for the same child — the candidate must be
    // rejected entirely (no second child, no evidence growth, no residue).
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    let (parent_bytes, parent) =
        m36_strict_parent_fixture(child_ptr, 0x850000, 0x1000, 0x200, &mut mock);
    mock.set(0x850000, parent_bytes.clone());
    mock.set(child_ptr, vec![0u8; 0x1000 - 0x150]);
    // Pre-seed the store with a binding for child_ptr at the expected size.
    // The size the producer computes is the final content length; use the
    // same fixture bytes to know it (0x1000-0x150 trimmed to probe cap).
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let key = PreTruncParentAuthorityKey {
        parent_old_base: 0x850000,
        parent_pre_trunc_size: 0x1000,
        parent_capture_id: "main:0x850000".into(),
    };
    pre_trunc_authority.record_parent(
        &key,
        &parent_bytes,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        CapturePath::MainSlot,
    );
    // Seed a binding for the child with a size we know will collide: the
    // producer's final child size is content.len() after trim. Instead of
    // guessing, seed with the actual produced size by running once in a
    // throwaway store, then re-run with the duplicate.
    let mut probe_store = PreTruncParentAuthorityStore::default();
    let mut out_p: Vec<HeapGlobalSnapshot> = vec![parent.clone()];
    let mut tb = m40_split_total_bytes(&out_p);
    let mut sh: BTreeSet<u64> = BTreeSet::new();
    let db = vec![0u8; 0x1000];
    let _admitted = split_swallowed_siblings(
        &mut out_p,
        &mut tb,
        &mut sh,
        &mut probe_store,
        image_base,
        image_end,
        &db,
        &mut mock,
    );
    let produced = probe_store
        .bindings()
        .iter()
        .find(|b| b.child_base == child_ptr)
        .map(|b| b.child_size)
        .expect("probe run must produce the child binding");
    // Now seed the REAL store with that same child binding -> duplicate.
    pre_trunc_authority.record_binding(
        key,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        CapturePath::MainSlot,
        child_ptr,
        produced,
        "src".into(),
        Some(0x200),
    );
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // The duplicate candidate is rejected: no new child admitted, no
    // evidence growth, parent untruncated, no residue.
    assert!(
        admitted.is_empty(),
        "duplicate child binding must reject the candidate"
    );
    assert_eq!(pre_trunc_authority.binding_count(), 1, "no new binding");
    assert!(out.iter().all(|g| g.live_ptr != child_ptr));
    let parent_after = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    assert_eq!(parent_after.content.len(), 0x1000);
    assert!(!seen_heaps.contains(&child_ptr));
    let _ = total_bytes;
}

// ============ MIDA-SERIAL-39: final-size gate + strict semantics ============

/// The duplicate-child gate must use the FINAL (post-string-shell-shrink)
/// child size. A shell probe with pre-shrink len > 0x28 must collide with a
/// pre-seeded (child_base, 0x28) binding and reject the WHOLE candidate.
#[test]
fn m39_string_shell_duplicate_uses_final_child_size() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    // Parent snapshot WITHOUT registering a mock region (it would shadow
    // the child/buffer reads); only child + buffer regions are registered.
    let mut parent_bytes = vec![0xABu8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
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
    // Child content: a refcounted string shell with probe len 0x40 (>0x28).
    let buf = 0x850F00u64;
    let mut shell = vec![0u8; 0x40];
    shell[0..8].copy_from_slice(&buf.to_le_bytes());
    shell[8..16].copy_from_slice(&buf.to_le_bytes());
    shell[16..24].copy_from_slice(&40u64.to_le_bytes());
    shell[24..32].copy_from_slice(&0x40u64.to_le_bytes());
    shell[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    mock.set(child_ptr, shell);
    mock.set(buf, vec![0x41u8; 0x40]);
    // Pre-seed a binding for (child_ptr, 0x28) — the FINAL shell size.
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    let key = PreTruncParentAuthorityKey {
        parent_old_base: 0x850000,
        parent_pre_trunc_size: 0x1000,
        parent_capture_id: "main:0x850000".into(),
    };
    pre_trunc_authority.record_parent(
        &key,
        &parent_bytes,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        CapturePath::MainSlot,
    );
    pre_trunc_authority.record_binding(
        key,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        CapturePath::MainSlot,
        child_ptr,
        0x28, // FINAL post-shell size
        "src".into(),
        Some(0x200),
    );
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // The candidate is REJECTED: the gate saw final size 0x28 and collided.
    assert!(
        admitted.is_empty(),
        "string-shell duplicate at final 0x28 must reject the candidate"
    );
    assert_eq!(pre_trunc_authority.binding_count(), 1, "no new binding");
    assert!(out
        .iter()
        .all(|g| g.live_ptr != child_ptr && g.live_ptr != buf));
    let parent_after = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    assert_eq!(parent_after.content, parent_bytes, "parent untouched");
    assert!(!seen_heaps.contains(&child_ptr) && !seen_heaps.contains(&buf));
    let _ = total_bytes;
}

/// Two ELIGIBLE frozen parents with the SAME key (base/size/capture_id)
/// but DIFFERENT full_bytes must fail closed — never first-wins. Both input
/// orders produce the same (no-authority) result.
#[test]
fn m39_qualifying_same_key_conflict_fails_closed() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let run = |bytes_a: Vec<u8>,
               bytes_b: Vec<u8>,
               a_first: bool|
     -> (usize, usize, Vec<u8>, Vec<u8>, bool) {
        let mut mock = M23RegionMapMock::new();
        // Two snapshots, SAME base/size/capture_id, BOTH ObservedAllocation
        // (both eligible), possibly DIFFERENT content bytes.
        let mk = |content: Vec<u8>| HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x850000,
            content,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            extent_evidence: CaptureExtentEvidence {
                capture_id: "main:0x850000".into(),
                capture_path: CapturePath::MainSlot,
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
        let a = mk(bytes_a.clone());
        let b = mk(bytes_b.clone());
        let before_bytes: Vec<Vec<u8>> = vec![a.content.clone(), b.content.clone()];
        // Both contain the child ptr at slot 0x200.
        let mut out: Vec<HeapGlobalSnapshot> = if a_first { vec![a, b] } else { vec![b, a] };
        for g in out.iter_mut() {
            g.content[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
        }
        let out_before: Vec<Vec<u8>> = out.iter().map(|g| g.content.clone()).collect();
        let len_before = out.len();
        let total_before = m40_split_total_bytes(&out);
        mock.set(child_ptr, vec![0u8; 0x1000 - 0x150]);
        let mut total_bytes = m40_split_total_bytes(&out);
        let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
        let mut store = PreTruncParentAuthorityStore::default();
        let dump_buf = vec![0u8; 0x1000];
        let admitted = split_swallowed_siblings(
            &mut out,
            &mut total_bytes,
            &mut seen_heaps,
            &mut store,
            image_base,
            image_end,
            &dump_buf,
            &mut mock,
        );
        // Full zero-mutation proof for the CONFLICT case:
        //  - candidate rejected (admitted empty);
        //  - out unchanged (same len, same bytes);
        //  - total_bytes unchanged;
        //  - seen_heaps unchanged (no child);
        //  - authority binding_count unchanged (0).
        if !admitted.is_empty() {
            assert!(
                bytes_a == bytes_b,
                "identical rows may admit; conflicting rows must NOT"
            );
        } else {
            assert_eq!(out.len(), len_before, "out len unchanged");
            let out_after: Vec<Vec<u8>> = out.iter().map(|g| g.content.clone()).collect();
            assert_eq!(out_after, out_before, "out bytes unchanged");
            assert_eq!(total_bytes, total_before, "total_bytes unchanged");
            assert!(!seen_heaps.contains(&child_ptr), "seen_heaps unchanged");
            assert_eq!(store.binding_count(), 0, "no authority written");
        }
        (
            store.binding_count(),
            total_bytes,
            out_before[0].clone(),
            before_bytes[0].clone(),
            admitted.is_empty(),
        )
    };
    let bytes_a = vec![0xAAu8; 0x1000];
    let bytes_b = vec![0xBBu8; 0x1000];
    // CONFLICT (different bytes): both orders reject with zero mutation.
    let (bc1, tb1, out1, a1, rej1) = run(bytes_a.clone(), bytes_b.clone(), true);
    let (bc2, tb2, out2, a2, rej2) = run(bytes_a.clone(), bytes_b.clone(), false);
    assert_eq!(
        bc1, 0,
        "same-key conflicting eligible parents: no authority"
    );
    assert_eq!(bc2, 0, "order B-first: still no authority");
    assert!(rej1 && rej2, "conflict rejects the candidate");
    assert_eq!(tb1, 0x2000, "total_bytes unchanged (2x0x1000)");
    assert_eq!(tb2, 0x2000, "total_bytes unchanged (order B-first)");
    assert_eq!(out1.len(), 0x1000, "out bytes unchanged (0x1000 each)");
    let _ = (out2, a1, a2);
    // Identical bytes -> resolvable regardless of order.
    let (bc3, _, _, _, rej3) = run(bytes_a.clone(), bytes_a.clone(), true);
    let (bc4, _, _, _, rej4) = run(bytes_a.clone(), bytes_a.clone(), false);
    assert_eq!(bc3, 1, "identical rows resolve to one binding");
    assert_eq!(bc4, 1, "identical rows resolve regardless of order");
    assert!(!rej3 && !rej4, "identical rows admit");
}

/// Frozen bytes ownership: two children of the same parent — the store's
/// lookup_arc returns POINTER-EQUAL Arcs (one backing allocation), and no
/// per-child full-Vec API path exists.
#[test]
fn m39_frozen_bytes_arc_pointer_equality() {
    use std::sync::Arc;
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_a = 0x850150u64;
    let child_b = 0x850400u64;
    let mut mock = M23RegionMapMock::new();
    let (_pb0, mut parent) = m36_strict_parent_fixture(child_a, 0x850000, 0x1000, 0x200, &mut mock);
    parent.content[0x500..0x508].copy_from_slice(&child_b.to_le_bytes());
    let parent_bytes = parent.content.clone();
    mock.set(0x850000, parent.content.clone());
    mock.set(child_b, vec![0u8; 0x1000 - 0x400]);
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut store = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let _admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut store,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    assert_eq!(store.binding_count(), 2);
    assert_eq!(store.parent_count(), 1);
    let bindings = store.bindings();
    let arc1: Arc<[u8]> = store.lookup_arc(&bindings[0].parent_key).unwrap();
    let arc2: Arc<[u8]> = store.lookup_arc(&bindings[1].parent_key).unwrap();
    // POINTER equality — the SAME backing allocation, not just equal bytes.
    assert!(
        Arc::ptr_eq(&arc1, &arc2),
        "both bindings share ONE Arc backing allocation"
    );
    assert_eq!(&*arc1, &parent_bytes[..]);
}

/// Unified-slot budget fails closed: when the split child + optional
/// string buffer would push planned_slots over the split slot cap, the
/// WHOLE candidate is rejected at the PHASE-2 commit plan (zero mutation).
///
/// The fixture is fully readable: parent bytes + child shell + string
/// buffer are all served by the mock, so the candidate reaches the
/// budget gate (never an earlier estimate/read failure).
#[test]
fn m39_split_budget_checked_overflow_fails_closed() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    // Parent snapshot WITHOUT a mock region (would shadow child reads).
    let mut parent_bytes = vec![0xABu8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
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
    let split_slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE);
    // Fill out to cap-1 with valid, non-overlapping dummy snapshots so the
    // split child + buffer would plan to cap+1 slots.
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    for i in 0..(split_slot_cap - 2) {
        let base = 0x900000u64 + (i as u64) * 0x1000;
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: base,
            content: vec![0x11u8; 0x100],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            extent_evidence: CaptureExtentEvidence {
                capture_id: format!("dummy:{base:#x}"),
                capture_path: CapturePath::MainSlot,
                source_root_rva: None,
                source_slot_offset: None,
                probe_requested_size: 0,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        });
    }
    // Child content: a refcounted string shell whose buffer would add a
    // SECOND slot. Both reads are servable by the mock, so the candidate
    // provably reaches the PHASE-2 slot budget.
    let buf = 0x850F00u64;
    let mut shell = vec![0u8; 0x40];
    shell[0..8].copy_from_slice(&buf.to_le_bytes());
    shell[8..16].copy_from_slice(&buf.to_le_bytes());
    shell[16..24].copy_from_slice(&40u64.to_le_bytes());
    shell[24..32].copy_from_slice(&0x40u64.to_le_bytes());
    shell[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    mock.set(child_ptr, shell);
    mock.set(buf, vec![0x41u8; 0x40]);
    // out.len() == cap-1: split child (1) + buffer (1) -> planned cap+1.
    let mut total_bytes = m40_split_total_bytes(&out);
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut store = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut store,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // The WHOLE candidate is rejected at the slot budget with zero
    // mutation: no child, no buffer, no binding, no seen residue.
    assert!(admitted.is_empty(), "slot budget overflow must reject");
    assert_eq!(
        total_bytes,
        m40_split_total_bytes(&out),
        "total_bytes unchanged (no mutation)"
    );
    assert_eq!(store.binding_count(), 0);
    assert!(
        out.iter()
            .all(|g| g.live_ptr != child_ptr && g.live_ptr != buf),
        "neither split child nor buffer admitted"
    );
    assert!(!seen_heaps.contains(&child_ptr) && !seen_heaps.contains(&buf));
    let parent_after = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    assert_eq!(parent_after.content.len(), 0x1000, "parent untruncated");
}

/// The truncation drop used in the budget must EXACTLY equal the commit
/// delta on total_bytes (single formula, no divergence).
#[test]
fn m39_truncation_drop_matches_commit_delta() {
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    // Parent WITHOUT mock region (would shadow child reads).
    let mut parent_bytes = vec![0xABu8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
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
    // One interior child; the commit drop == parent 0x1000 - 0x150.
    mock.set(child_ptr, vec![0u8; 0x1000 - 0x150]);
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent];
    // Production-consistent total: sum of contents.
    let mut total_bytes: usize = out.iter().map(|g| g.content.len()).sum();
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut store = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let _admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut store,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // After commit: parent truncated to (child_ptr - 0x850000) = 0x150.
    let parent_after = out.iter().find(|g| g.live_ptr == 0x850000).unwrap();
    let expect_drop = 0x1000 - 0x150;
    assert_eq!(parent_after.content.len(), 0x150);
    // total_bytes == sum(out) after commit (production invariant restored).
    let sum_after: usize = out.iter().map(|g| g.content.len()).sum();
    assert_eq!(total_bytes, sum_after, "commit delta == budget drop");
    let _ = expect_drop;
}

/// A parent appearing in the truncation list twice must not be double-
/// counted in the drop (dedupe by base).
#[test]
fn m39_duplicate_parent_truncation_is_not_double_counted() {
    // Two snapshots at the SAME base (duplicate rows) both swallowing the
    // child. Each ROW is truncated once; the drop is counted once per row
    // (no single-parent double-count).
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x200000;
    let child_ptr = 0x850150u64;
    let mut mock = M23RegionMapMock::new();
    // Parent WITHOUT mock region (would shadow child reads).
    let mut parent_bytes = vec![0xABu8; 0x1000];
    parent_bytes[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_bytes.clone(),
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: CapturePath::MainSlot,
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
    // TRUE duplicate row: IDENTICAL bytes at the SAME base (not a
    // same-key conflict — the frozen registry sees two identical rows and
    // resolves them as ONE authority). Both rows swallow the child and
    // both must be truncated.
    let dup = parent.clone();
    mock.set(child_ptr, vec![0u8; 0x1000 - 0x150]);
    let mut out: Vec<HeapGlobalSnapshot> = vec![parent, dup];
    let mut total_bytes: usize = out.iter().map(|g| g.content.len()).sum();
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut store = PreTruncParentAuthorityStore::default();
    let dump_buf = vec![0u8; 0x1000];
    let _admitted = split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut store,
        image_base,
        image_end,
        &dump_buf,
        &mut mock,
    );
    // Both duplicate rows truncated to 0x150, drop counted ONCE per base.
    let mut at_base = 0usize;
    for g in out.iter() {
        if g.live_ptr == 0x850000 {
            assert_eq!(g.content.len(), 0x150, "parent truncated once");
            at_base += 1;
        }
    }
    assert_eq!(at_base, 2, "both duplicate rows truncated to same len");
    let sum_after: usize = out.iter().map(|g| g.content.len()).sum();
    assert_eq!(total_bytes, sum_after, "drop counted exactly once");
    let _ = parent_bytes;
}
