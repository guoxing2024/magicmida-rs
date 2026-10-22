//! End-to-end acceptance gate for the reference Themida v3 x64 case.
//!
//! # Why this exists
//!
//! Before this file there was **no** test that ran the unpack pipeline over a
//! real protected binary.  The 173-test suite covered pure functions and
//! synthetic PE structures, so the headline numbers of the only fully-successful
//! case (186 resolved imports / 9 modules / a product that launches) were
//! protected by nothing but a paragraph in `AGENTS.md`.  Someone could have
//! broken the trace loop and every test would still have been green.
//!
//! # How it runs
//!
//! This is a **`#[ignore]`d** integration test: it spawns the real
//! `mida-cli` binary against a real sample under a debugger, which needs
//! Windows, the ScyllaHide helper binaries next to the CLI, and the sample
//! itself.  Run it explicitly:
//!
//! ```text
//! cargo test -p mida-packers-themida --test e2e_gate -- --ignored --nocapture
//! ```
//!
//! # Where the sample identity comes from
//!
//! Not from a literal in this file.  The sample path and its expected SHA-256
//! come from the case manifest at `crates/packers/themida/tests/cases/`
//! (same shape as the upstream `lab/cases/v2/*.json`), so rotating a sample is
//! a manifest edit, not a code edit.  The upstream project gates on "no sample
//! hashes in production code"; this file keeps that spirit for tests too.

use std::path::{Path, PathBuf};
use std::process::Command;

use mida_pe::PeHeader;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Case manifest
// ---------------------------------------------------------------------------

/// Minimal case manifest — the subset this gate needs.
#[derive(Debug)]
struct CaseManifest {
    case_id: String,
    sample_path: PathBuf,
    sample_sha256: String,
    sample_size: u64,
    /// Expected `resolved` count from the IAT trace.
    expect_resolved: usize,
    /// Expected `failed` count from the IAT trace.
    expect_failed: usize,
    /// Expected module count in the rebuilt import table.
    expect_module_count: usize,
    /// Expected thunk count in the rebuilt import table.
    expect_thunk_count: usize,
    /// Expected IAT slot count.
    expect_iat_slots: usize,
    /// Expected output size in bytes.
    expect_output_size: u64,
    /// Expected output SHA-256.  May be empty when the case is known to be
    /// non-reproducible; the gate then only checks structure.
    expect_output_sha256: String,
}

/// Parse the tiny key/value manifest format used by this directory.
///
/// Deliberately not serde: adding a dependency for a test fixture is not worth
/// it, and a hand-rolled parser keeps the file readable in review.
fn load_manifest(path: &Path) -> CaseManifest {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read manifest {}: {e}", path.display()));

    let mut get = |key: &str| -> String {
        text.lines()
            .map(str::trim)
            .find(|l| !l.starts_with('#') && l.split(':').next() == Some(key))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_else(|| panic!("manifest {} is missing key `{key}`", path.display()))
    };
    let num = |key: &str| -> usize {
        get(key)
            .parse()
            .unwrap_or_else(|e| panic!("manifest key `{key}` is not a number: {e}"))
    };

    let case_id = get("case_id");
    let sample_path = PathBuf::from(get("sample_path"));
    let sample_sha256 = get("sample_sha256").to_lowercase();
    let sample_size = num("sample_size") as u64;
    let expect_resolved = num("expect_resolved");
    let expect_failed = num("expect_failed");
    let expect_module_count = num("expect_module_count");
    let expect_thunk_count = num("expect_thunk_count");
    let expect_iat_slots = num("expect_iat_slots");
    let expect_output_size = num("expect_output_size") as u64;
    let expect_output_sha256 = get("expect_output_sha256").to_lowercase();

    CaseManifest {
        case_id,
        sample_path,
        sample_sha256,
        sample_size,
        expect_resolved,
        expect_failed,
        expect_module_count,
        expect_thunk_count,
        expect_iat_slots,
        expect_output_size,
        expect_output_sha256,
    }
}

fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases/guoxing_shiguang.case")
}

fn sha256_of(path: &Path) -> String {
    let data = std::fs::read(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut h = Sha256::new();
    h.update(&data);
    format!("{:x}", h.finalize())
}

/// Locate the CLI binary that belongs to this test run.
fn mida_cli_path() -> PathBuf {
    // target/<profile>/deps/<test-exe> → target/<profile>/mida-cli.exe
    let mut dir = std::env::current_exe().expect("current_exe");
    dir.pop(); // deps/
    dir.pop(); // <profile>/
    let exe = dir.join("mida-cli.exe");
    assert!(
        exe.exists(),
        "mida-cli.exe not found at {} — build it first: cargo build --release -p mida-cli",
        exe.display()
    );
    exe
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Full pipeline over the reference sample: unpack, then assert the frozen
/// metrics AND that the product still loads.
///
/// Ignored by default because it needs a real sample, a Windows host, and the
/// ScyllaHide helpers.  This is the test that makes the golden numbers mean
/// something.
#[test]
#[ignore = "requires the protected sample, a Windows host, and ScyllaHide helpers"]
fn e2e_reference_case_matches_golden_record() {
    let case = load_manifest(&manifest_path());

    // ---- 1. sample identity (fail-closed: wrong bytes = stop, do not run) ----
    assert!(
        case.sample_path.exists(),
        "[{}] sample not found at {}",
        case.case_id,
        case.sample_path.display()
    );
    let size = std::fs::metadata(&case.sample_path).unwrap().len();
    assert_eq!(
        size, case.sample_size,
        "[{}] sample size mismatch — refusing to run",
        case.case_id
    );
    let digest = sha256_of(&case.sample_path);
    assert_eq!(
        digest, case.sample_sha256,
        "[{}] sample SHA-256 mismatch — refusing to run (identity is not a path)",
        case.case_id
    );

    // ---- 2. run the real pipeline ----
    let cli = mida_cli_path();
    let out_dir = std::env::temp_dir().join(format!("mida-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&out_dir).expect("create temp out dir");
    let out_exe = out_dir.join("gate.exe");
    let _ = std::fs::remove_file(&out_exe);

    let output = Command::new(&cli)
        .arg("/unpack")
        .arg(&case.sample_path)
        .arg("-o")
        .arg(&out_exe)
        .arg("-v")
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", cli.display()));

    let log = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    let status = output.status.code().unwrap_or(-1);

    // Keep the log next to the artifact for forensics on failure.
    let log_path = out_dir.join("gate.log");
    std::fs::write(&log_path, &log).ok();

    assert_eq!(
        status, 0,
        "[{}] mida-cli exited {status}; log at {}",
        case.case_id,
        log_path.display()
    );

    // ---- 3. trace metrics ----
    let resolved = extract_usize(&log, "IAT trace complete: ")
        .unwrap_or_else(|| panic!("[{}] no `IAT trace complete:` line in log", case.case_id));
    let (resolved, failed) = resolved;
    assert_eq!(
        resolved, case.expect_resolved,
        "[{}] resolved-import count regressed (log: {})",
        case.case_id,
        log_path.display()
    );
    assert_eq!(
        failed, case.expect_failed,
        "[{}] failed-slot count changed (log: {})",
        case.case_id,
        log_path.display()
    );

    // ---- 4. rebuilt import table ----
    let (modules, thunks) = extract_pair(&log, "Import table reconstructed module_count=")
        .unwrap_or_else(|| panic!("[{}] no import-table line in log", case.case_id));
    assert_eq!(
        modules, case.expect_module_count,
        "[{}] module count regressed (log: {})",
        case.case_id,
        log_path.display()
    );
    assert_eq!(
        thunks, case.expect_thunk_count,
        "[{}] thunk count regressed (log: {})",
        case.case_id,
        log_path.display()
    );

    // ---- 5. IAT slot scan covered the whole table (no early abort) ----
    let slots = extract_iat_slots(&log)
        .unwrap_or_else(|| panic!("[{}] no IAT boundary line in log", case.case_id));
    assert_eq!(
        slots, case.expect_iat_slots,
        "[{}] IAT slot count changed — the scan is aborting early (log: {})",
        case.case_id,
        log_path.display()
    );

    // ---- 6. product structure ----
    assert!(out_exe.exists(), "[{}] no product written", case.case_id);
    let out_len = std::fs::metadata(&out_exe).unwrap().len();
    assert_eq!(
        out_len, case.expect_output_size,
        "[{}] product size changed",
        case.case_id
    );

    let pe = PeHeader::from_file(&out_exe).expect("product must parse as PE");
    assert!(pe.is_64bit, "[{}] product is not PE32+", case.case_id);
    assert_ne!(pe.entry_point, 0, "[{}] product has a null entry point", case.case_id);

    // Every section must lie inside the declared image.
    let image_size = pe.size_of_image();
    for s in &pe.sections {
        let end = s.virtual_address.saturating_add(s.virtual_size);
        assert!(
            end <= image_size,
            "[{}] section `{}` ends at {:#x}, beyond SizeOfImage {:#x}",
            case.case_id,
            s.name,
            end,
            image_size
        );
    }

    // The import directory must be populated — a zeroed one means the rebuild
    // silently produced nothing.
    const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
    let import_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    assert_ne!(
        import_dir.virtual_address, 0,
        "[{}] product has no import directory — import rebuild failed silently",
        case.case_id
    );

    // ---- 7. byte-level reproducibility (when the case declares it) ----
    if !case.expect_output_sha256.is_empty() {
        let out_digest = sha256_of(&out_exe);
        assert_eq!(
            out_digest, case.expect_output_sha256,
            "[{}] product SHA-256 drifted from the golden record",
            case.case_id
        );
    }

    // ---- 8. the product must actually load ----
    //
    // P-4 (upstream): a frozen product must be launched on the spot; a
    // non-zero/0xC0000005 exit means the dump is structurally wrong even if
    // every counter above matched.
    let child = Command::new(&out_exe)
        .spawn()
        .unwrap_or_else(|e| panic!("[{}] cannot launch product: {e}", case.case_id));
    std::thread::sleep(std::time::Duration::from_secs(5));
    let mut child = child;
    match child.try_wait().expect("try_wait") {
        None => {
            // Still running — that is the pass condition for a GUI target.
            let _ = child.kill();
            let _ = child.wait();
        }
        Some(st) => panic!(
            "[{}] product exited immediately with {st} — dump is not loadable (log: {})",
            case.case_id,
            log_path.display()
        ),
    }

    let _ = std::fs::remove_dir_all(&out_dir);
}

// ---------------------------------------------------------------------------
// Log scraping helpers
// ---------------------------------------------------------------------------

/// `IAT trace complete: {resolved} resolved, {failed} failed`
fn extract_usize(log: &str, marker: &str) -> Option<(usize, usize)> {
    let line = log.lines().rev().find(|l| l.contains(marker))?;
    let rest = line.split_once(marker)?.1;
    let resolved: usize = rest.split_whitespace().next()?.parse().ok()?;
    let failed: usize = rest
        .split_once("resolved,")?
        .1
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((resolved, failed))
}

/// `Import table reconstructed module_count={m} thunk_count={t}`
fn extract_pair(log: &str, marker: &str) -> Option<(usize, usize)> {
    let line = log.lines().rev().find(|l| l.contains(marker))?;
    let rest = line.split_once(marker)?.1;
    let modules: usize = rest.split_whitespace().next()?.parse().ok()?;
    let thunks: usize = rest
        .split_once("thunk_count=")?
        .1
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((modules, thunks))
}

/// `IAT boundaries: start=..., end=..., size=... ({slots} slots), blocks={n}`
fn extract_iat_slots(log: &str) -> Option<usize> {
    let line = log.lines().rev().find(|l| l.contains("IAT boundaries:"))?;
    let tail = line.split_once('(')?.1; // "{slots} slots), blocks=..."
    tail.split_whitespace().next()?.parse().ok()
}

// ---------------------------------------------------------------------------
// Parser self-tests (these run in the normal suite)
// ---------------------------------------------------------------------------

#[test]
fn log_scrapers_parse_real_lines() {
    let log = "\
[INFO] IAT boundaries: start=0x7ff6f5e536e0, end=0x7ff6f5e55818, size=8504 (1063 slots), blocks=14
[GOOD] IAT trace complete: 186 resolved, 8 failed
[INFO] Import table reconstructed module_count=9 thunk_count=186
";
    assert_eq!(extract_iat_slots(log), Some(1063));
    assert_eq!(extract_usize(log, "IAT trace complete: "), Some((186, 8)));
    assert_eq!(
        extract_pair(log, "Import table reconstructed module_count="),
        Some((9, 186))
    );
}

#[test]
fn log_scrapers_return_none_on_missing_marker() {
    assert_eq!(extract_usize("nothing here", "IAT trace complete: "), None);
    assert_eq!(extract_pair("nothing here", "module_count="), None);
    assert_eq!(extract_iat_slots("nothing here"), None);
}

#[test]
fn manifest_is_present_and_well_formed() {
    let case = load_manifest(&manifest_path());
    assert_eq!(case.case_id, "guoxing_shiguang");
    assert!(!case.sample_sha256.is_empty());
    assert_eq!(case.sample_sha256.len(), 64, "SHA-256 must be 64 hex chars");
    assert!(case.expect_resolved > 0);
    assert!(case.expect_module_count > 0);
    assert!(case.expect_iat_slots > 0);
}
