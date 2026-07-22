//! Structural gate coverage using runtime-synthesized PE images only.

use mida_acceptance::{
    check_static, sha256_hex, CheckStaticOptions, GateStatus, Verdict, ROLE_CANDIDATE,
};

// Re-implement a thin builder mirror for integration tests (crate test_support is private).
// Integration tests only see the public API; synthesize PE via shared logic inlined below.

#[allow(dead_code)]
mod synth {
    include!("../src/test_support/pe_builder.rs");
}

use synth::{build_pe, CorruptMode, PeBuildOptions, PeKind};

fn opts() -> CheckStaticOptions {
    CheckStaticOptions {
        role: Some(ROLE_CANDIDATE.to_string()),
        ..Default::default()
    }
}

#[test]
fn pe32_plus_positive() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_ne!(report.verdict, Verdict::Accepted);
}

#[test]
fn pe32_positive() {
    let pe = build_pe(&PeBuildOptions::pe32());
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
}

#[test]
fn pe32_plus_with_import_and_reloc() {
    let mut o = PeBuildOptions::pe32_plus();
    o.include_import = true;
    o.include_reloc = true;
    let pe = build_pe(&o);
    let report = check_static(&pe, &opts());
    assert_eq!(
        report.verdict,
        Verdict::StructuralPassBehaviorPending,
        "{:?}",
        report.failures
    );
}

#[test]
fn truncated_file_rejected() {
    let pe = build_pe(&PeBuildOptions {
        corrupt: CorruptMode::TruncateFile(16),
        ..PeBuildOptions::pe32_plus()
    });
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report
        .failures
        .iter()
        .any(|f| f.gate_id == "headers_bounds"));
}

#[test]
fn section_raw_overflow_rejected() {
    let pe = build_pe(&PeBuildOptions {
        corrupt: CorruptMode::SectionRawOverflow,
        ..PeBuildOptions::pe32_plus()
    });
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report
        .failures
        .iter()
        .any(|f| f.code.contains("raw") || f.gate_id == "sections_ranges"));
}

#[test]
fn section_va_overlap_rejected() {
    let pe = build_pe(&PeBuildOptions {
        corrupt: CorruptMode::SectionVaOverlap,
        ..PeBuildOptions::pe32_plus()
    });
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report
        .failures
        .iter()
        .any(|f| f.code == "section_va_overlap"));
}

#[test]
fn invalid_entry_point_rejected() {
    let pe = build_pe(&PeBuildOptions {
        corrupt: CorruptMode::BadEntryPoint,
        ..PeBuildOptions::pe32_plus()
    });
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report.failures.iter().any(|f| f.gate_id == "entry_point"));
}

#[test]
fn malformed_import_thunk_rejected() {
    let pe = build_pe(&PeBuildOptions {
        include_import: true,
        corrupt: CorruptMode::BadImportThunk,
        ..PeBuildOptions::pe32_plus()
    });
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report.failures.iter().any(|f| f.gate_id == "imports_iat"));
}

#[test]
fn invalid_tls_rejected() {
    let pe = build_pe(&PeBuildOptions {
        corrupt: CorruptMode::BadTlsSize,
        ..PeBuildOptions::pe32_plus()
    });
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report.failures.iter().any(|f| f.gate_id == "tls_directory"));
}

#[test]
fn invalid_reloc_rejected() {
    let pe = build_pe(&PeBuildOptions {
        corrupt: CorruptMode::BadRelocBlock,
        ..PeBuildOptions::pe32_plus()
    });
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report
        .failures
        .iter()
        .any(|f| f.gate_id == "reloc_directory"));
}

#[test]
fn invalid_exception_rejected() {
    let pe = build_pe(&PeBuildOptions {
        corrupt: CorruptMode::BadExceptionSize,
        ..PeBuildOptions::pe32_plus()
    });
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report
        .failures
        .iter()
        .any(|f| f.gate_id == "exception_directory"));
}

#[test]
fn dynamic_base_without_reloc_rejected() {
    let pe = build_pe(&PeBuildOptions {
        corrupt: CorruptMode::DynamicBaseNoReloc,
        ..PeBuildOptions::pe32_plus()
    });
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report
        .failures
        .iter()
        .any(|f| f.gate_id == "aslr_reloc_consistency"));
}

#[test]
fn digest_mismatch_rejected() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let report = check_static(
        &pe,
        &CheckStaticOptions {
            expected_sha256: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            ..opts()
        },
    );
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(report
        .failures
        .iter()
        .any(|f| f.gate_id == "artifact_identity"));
    // Structural gates skipped
    assert!(report
        .gates
        .iter()
        .any(|g| g.id == "headers_bounds" && g.status == GateStatus::Skip));
}

#[test]
fn digest_match_passes_identity() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let dig = sha256_hex(&pe);
    let report = check_static(
        &pe,
        &CheckStaticOptions {
            expected_sha256: Some(dig),
            ..opts()
        },
    );
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
}

#[test]
fn never_accepted() {
    for kind in [PeKind::Pe32, PeKind::Pe32Plus] {
        let mut o = PeBuildOptions::default();
        o.kind = kind;
        if matches!(kind, PeKind::Pe32) {
            o = PeBuildOptions::pe32();
        }
        let pe = build_pe(&o);
        let report = check_static(&pe, &opts());
        assert_ne!(report.verdict, Verdict::Accepted);
    }
    // garbage
    let report = check_static(b"not a pe", &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
    assert_ne!(report.verdict, Verdict::Accepted);
}

#[test]
fn malformed_input_no_panic() {
    let samples: &[&[u8]] = &[
        b"",
        b"M",
        b"MZ",
        b"MZ\0\0",
        &[0u8; 64],
        b"MZ\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0",
        &[0xFFu8; 1024],
    ];
    for s in samples {
        let report = check_static(s, &opts());
        assert_eq!(report.verdict, Verdict::Rejected);
        let _ = report.to_json().unwrap();
    }
}

#[test]
fn truncate_after_headers_rejected() {
    let pe = build_pe(&PeBuildOptions {
        corrupt: CorruptMode::TruncateAfterHeaders,
        ..PeBuildOptions::pe32_plus()
    });
    // Headers claim raw section beyond file — should fail section raw oob
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::Rejected);
}
