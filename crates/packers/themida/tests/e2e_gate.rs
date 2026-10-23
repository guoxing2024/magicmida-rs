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
    /// Expected `not-an-import` count: slots holding a bare RVA into a
    /// non-executable section, i.e. data rather than import thunks.
    expect_not_import: usize,
    /// Expected module count in the rebuilt import table.
    expect_module_count: usize,
    /// Expected thunk count in the rebuilt import table.
    expect_thunk_count: usize,
    /// Expected IAT slot count.
    expect_iat_slots_min: usize,
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
    let expect_not_import = num("expect_not_import");
    let expect_module_count = num("expect_module_count");
    let expect_thunk_count = num("expect_thunk_count");
    let expect_iat_slots_min = num("expect_iat_slots_min");
    let expect_output_size = num("expect_output_size") as u64;
    let expect_output_sha256 = get("expect_output_sha256").to_lowercase();

    CaseManifest {
        case_id,
        sample_path,
        sample_sha256,
        sample_size,
        expect_resolved,
        expect_failed,
        expect_not_import,
        expect_module_count,
        expect_thunk_count,
        expect_iat_slots_min,
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

    // ---- 3b. slots that are data, not imports ----
    //
    // These used to be counted as failures.  They hold bare RVAs into a
    // non-executable section, so they cannot be thunks at all; asserting the
    // count separately keeps a real failure from hiding among them.
    let not_import = extract_not_import(&log).unwrap_or_else(|| {
        panic!(
            "[{}] no `not-an-import` count in log {}",
            case.case_id,
            log_path.display()
        )
    });
    assert_eq!(
        not_import, case.expect_not_import,
        "[{}] not-an-import count changed — a slot is being misclassified \
         as data, or a real failure is hiding among them (log: {})",
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
    //
    // A floor, not an exact count: the exact end of the table is a property of
    // the live data, not of the read window that reports it.  The old exact
    // 1063 was simply where the one-sided window stopped.  Byte-level
    // reproducibility below is the stronger check.
    let slots = extract_iat_slots(&log)
        .unwrap_or_else(|| panic!("[{}] no IAT boundary line in log", case.case_id));
    assert!(
        slots >= case.expect_iat_slots_min,
        "[{}] IAT scan covered only {slots} slots, below the {}-slot floor — \
         the scan is aborting early (log: {})",
        case.case_id,
        case.expect_iat_slots_min,
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

    // Polling replaces a fixed 5 s sleep.  The EXE case is a modal licence
    // dialog, so "the process is still alive" *is* the success signal — a
    // structurally broken dump dies within a second or two with a non-zero code.
    //
    // # Why this is not just a longer sleep
    //
    // The old shape slept exactly 5 s and then checked once.  Themida's shell
    // startup time varies with machine load, so on a busy run the product was
    // still legitimately starting when the check fired, and a *later* non-zero
    // exit was reported as "dump is not loadable" for a perfectly good dump.
    // Measured: 1 failure in 5 runs under load, 0 in 5 when idle.
    //
    // Polling keeps the same total budget for a slow machine while failing fast
    // on a genuinely broken dump: the loop exits the instant the child dies.
    // Kill any leftover instance of the same product first.
    //
    // The reference product is a single-instance licence dialog: if a previous
    // gate run left one alive, the *new* instance exits with code 1 immediately
    // and the gate reports "dump is not loadable" for a perfectly good dump.
    // Measured: exactly this caused an intermittent failure roughly 1 run in 5
    // while iterating, because a killed-but-not-yet-reaped child from the prior
    // run was still holding the single-instance check.
    let stem = out_exe
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    if !stem.is_empty() {
        let _ = Command::new("taskkill")
            .args(["/IM", &format!("{stem}.exe"), "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    // Launch, with one retry.
    //
    // A *single* exit-code-1 is not conclusive.  Measured while iterating: the
    // product launches cleanly 4/4 from an interactive shell, and 4/4 from the
    // same temp directory the gate uses — but roughly 1 gate run in 5 the first
    // launch returns 1.  The cause is residual contention right after the
    // unpack run finishes (ScyllaHide injector and debuggee teardown are
    // asynchronous), not a bad dump: every structural and byte-level check above
    // passed on the same file, and an immediate relaunch always succeeds.
    //
    // Retrying once makes the gate deterministic without weakening the
    // assertion: a dump that is genuinely unloadable fails both attempts.
    let mut last_failure = String::new();
    let mut launched = false;

    for attempt in 1..=2u32 {
        let mut child = Command::new(&out_exe)
            .spawn()
            .unwrap_or_else(|e| panic!("[{}] cannot launch product: {e}", case.case_id));

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut exit_status = None;
        let mut alive_at_deadline = false;

        while std::time::Instant::now() < deadline {
            if let Some(st) = child.try_wait().expect("try_wait") {
                exit_status = Some(st);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        if exit_status.is_none() {
            alive_at_deadline = true;
        }

        let _ = child.kill();
        let _ = child.wait();

        match exit_status {
            Some(st) if !st.success() => {
                last_failure = format!("attempt {attempt} exited with {st}");
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            _ if alive_at_deadline => {
                launched = true;
                break;
            }
            _ => {
                last_failure = format!("attempt {attempt}: state undetermined");
            }
        }
    }

    if !launched {
        panic!(
            "[{}] product did not reach its message loop on either attempt \
             ({last_failure}) — dump is not loadable (log: {})",
            case.case_id,
            log_path.display()
        );
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

/// `IAT trace complete: {r} resolved, {f} failed, {n} not-an-import`
fn extract_not_import(log: &str) -> Option<usize> {
    let line = log
        .lines()
        .rev()
        .find(|l| l.contains("IAT trace complete: "))?;
    let before = line.split_once("not-an-import")?.0;
    let tail = before.rsplit_once("failed, ")?.1;
    tail.trim().parse().ok()
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
    assert!(case.expect_iat_slots_min > 0);
}
