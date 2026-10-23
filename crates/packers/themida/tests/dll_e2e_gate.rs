//! End-to-end acceptance gate for the reference Themida v3 x64 **DLL** case.
//!
//! # Why this is a separate gate from `e2e_gate.rs`
//!
//! The EXE case can be accepted by launching its product: a GUI EXE that is
//! still running after five seconds is a working dump.  A DLL has no such
//! signal — `LoadLibrary` succeeding only proves the headers and the import
//! table are sound, not that the shell finished initialising.  The defect this
//! gate was written to catch was exactly that: the product loaded, its exports
//! resolved, and `GetAppVersion()` still answered `"0.0"` because `.bss` had
//! been captured before the shell wrote it.
//!
//! So this gate asserts **behaviour**, through a small C harness
//! (`tests/fixtures/dll_gate_harness.c`) that treats the product the way a real
//! host application would:
//!
//! 1. `LoadLibraryW` the product.
//! 2. Call `GetAppVersion()` and compare the string.
//! 3. Call `Run()` and require the window the product creates to appear.
//!
//! # Byte-level reproducibility
//!
//! This case used to be behaviour-only.  The last run-to-run difference was one
//! `.bss` qword, and `fix_hardcoded_addresses` was not the cause: the slot is
//! `__security_cookie`, written by MSVC's `__security_init_cookie` with a fresh
//! random seed per process.  `find_security_cookie_rvas()` now zeroes it at dump
//! time, which is the semantically correct file value (the loader re-randomises
//! when it sees zero), and the manifest carries a real SHA-256.  Structural,
//! byte-level, and behavioural checks all run.
//!
//! # Running it
//!
//! ```text
//! cargo test -p mida-packers-themida --test dll_e2e_gate -- --ignored --nocapture
//! ```
//!
//! Needs Windows, the ScyllaHide helpers next to `mida-cli`, `gcc` on `PATH`
//! (to build the harness), the sample itself, and — because the last assertion
//! is a real window — an interactive desktop session.  On a headless CI runner
//! the window assertion is the part that will not pass.

use std::path::{Path, PathBuf};
use std::process::Command;

use mida_pe::PeHeader;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Case manifest
// ---------------------------------------------------------------------------

/// The subset of the case manifest this gate needs.
#[derive(Debug)]
struct DllCase {
    case_id: String,
    sample_path: PathBuf,
    sample_sha256: String,
    sample_size: u64,
    expect_resolved: usize,
    expect_failed: usize,
    /// Slots holding a bare RVA into a non-executable section: data, not imports.
    expect_not_import: usize,
    /// Minimum IAT slot count — a floor, not an exact count.  The exact end of
    /// the table is a property of the data, not of the read window; see the
    /// manifest header.
    expect_iat_slots_min: usize,
    expect_output_size: u64,
    /// `none` disables the byte-level check; this case records a real hash.
    expect_output_sha256: String,
    expect_version: String,
    expect_window_class: String,
    expect_window_title: String,
}

fn load_manifest(path: &Path) -> DllCase {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read manifest {}: {e}", path.display()));

    let get = |key: &str| -> String {
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

    DllCase {
        case_id: get("case_id"),
        sample_path: PathBuf::from(get("sample_path")),
        sample_sha256: get("sample_sha256").to_lowercase(),
        sample_size: num("sample_size") as u64,
        expect_resolved: num("expect_resolved"),
        expect_failed: num("expect_failed"),
        expect_not_import: num("expect_not_import"),
        expect_iat_slots_min: num("expect_iat_slots_min"),
        expect_output_size: num("expect_output_size") as u64,
        expect_output_sha256: get("expect_output_sha256").to_lowercase(),
        expect_version: get("expect_version"),
        expect_window_class: get("expect_window_class"),
        expect_window_title: get("expect_window_title"),
    }
}

fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases/core_dll.case")
}

fn harness_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dll_gate_harness.c")
}

fn sha256_of(path: &Path) -> String {
    let data = std::fs::read(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut h = Sha256::new();
    h.update(&data);
    format!("{:x}", h.finalize())
}

/// Read `len` bytes at `rva` from a PE file on disk.
///
/// Uses the section table rather than assuming RVA == file offset: in a
/// *product* they differ (the dumper only guarantees that for the in-memory
/// image it works on).
fn read_dir_bytes(path: &Path, rva: u32, len: u32) -> Option<Vec<u8>> {
    let data = std::fs::read(path).ok()?;
    let pe = PeHeader::from_bytes(&data[..data.len().min(0x1000)]).ok()?;
    let sec = pe
        .sections
        .iter()
        .find(|s| rva >= s.virtual_address && rva < s.virtual_address.saturating_add(s.virtual_size))?;
    let delta = rva - sec.virtual_address;
    let off = sec.raw_offset as usize + delta as usize;
    let end = off.checked_add(len as usize)?;
    if end > data.len() {
        // The section may be shorter on disk than its virtual size.
        let avail = data.len().saturating_sub(off);
        return Some(data[off..off + avail].to_vec());
    }
    Some(data[off..end].to_vec())
}

/// Locate the CLI binary that belongs to this test run.
fn mida_cli_path() -> PathBuf {
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

/// Build the behaviour harness next to the test artifacts.
///
/// Compiled on demand rather than checked in as a binary: a committed `.exe`
/// cannot be reviewed, and the harness is 100 lines of plain Win32.
fn build_harness(out_dir: &Path) -> PathBuf {
    let exe = out_dir.join("dll_gate_harness.exe");
    let src = harness_source();
    assert!(src.exists(), "harness source missing at {}", src.display());

    let output = Command::new("gcc")
        .arg("-O2")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .output()
        .unwrap_or_else(|e| {
            panic!("cannot run gcc to build the harness (needed for the window check): {e}")
        });
    assert!(
        output.status.success(),
        "harness build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    exe
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires the protected DLL sample, a Windows desktop session, gcc, and ScyllaHide helpers"]
fn e2e_dll_case_matches_golden_record() {
    let case = load_manifest(&manifest_path());

    // ---- 1. sample identity (fail-closed) ----
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
    assert_eq!(
        sha256_of(&case.sample_path),
        case.sample_sha256,
        "[{}] sample SHA-256 mismatch — refusing to run (identity is not a path)",
        case.case_id
    );

    // ---- 2. run the real pipeline ----
    let cli = mida_cli_path();
    let out_dir = std::env::temp_dir().join(format!("mida-dll-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&out_dir).expect("create temp out dir");
    let out_dll = out_dir.join("gate.dll");
    let _ = std::fs::remove_file(&out_dll);

    let output = Command::new(&cli)
        .arg("/unpack")
        .arg(&case.sample_path)
        .arg("-o")
        .arg(&out_dll)
        .arg("-v")
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", cli.display()));

    let log = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    let status = output.status.code().unwrap_or(-1);

    let log_path = out_dir.join("gate.log");
    std::fs::write(&log_path, &log).ok();

    assert_eq!(
        status, 0,
        "[{}] mida-cli exited {status}; log at {}",
        case.case_id,
        log_path.display()
    );

    // ---- 3. trace metrics ----
    let (resolved, failed) = extract_trace_counts(&log).unwrap_or_else(|| {
        panic!(
            "[{}] no `IAT trace complete:` line in log {}",
            case.case_id,
            log_path.display()
        )
    });
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

    // ---- 3b. data slots are not failures ----
    let not_import = extract_not_import(&log).unwrap_or_else(|| {
        panic!(
            "[{}] no `not-an-import` count in log {}",
            case.case_id,
            log_path.display()
        )
    });
    assert_eq!(
        not_import, case.expect_not_import,
        "[{}] not-an-import count changed (log: {})",
        case.case_id,
        log_path.display()
    );

    // ---- 4. the IAT scan covered the whole table ----
    let slots = extract_iat_slots(&log).unwrap_or_else(|| {
        panic!(
            "[{}] no IAT boundary line in log {}",
            case.case_id,
            log_path.display()
        )
    });
    assert!(
        slots >= case.expect_iat_slots_min,
        "[{}] IAT scan covered only {slots} slots, below the {}-slot floor — \
         the scan is aborting early (log: {})",
        case.case_id,
        case.expect_iat_slots_min,
        log_path.display()
    );

    // ---- 5. product structure ----
    assert!(out_dll.exists(), "[{}] no product written", case.case_id);
    assert_eq!(
        std::fs::metadata(&out_dll).unwrap().len(),
        case.expect_output_size,
        "[{}] product size changed",
        case.case_id
    );

    let pe = PeHeader::from_file(&out_dll).expect("product must parse as PE");
    assert!(pe.is_64bit, "[{}] product is not PE32+", case.case_id);
    assert_ne!(
        pe.entry_point, 0,
        "[{}] product has a null entry point",
        case.case_id
    );

    const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
    let import_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    assert_ne!(
        import_dir.virtual_address, 0,
        "[{}] product has no import directory — import rebuild failed silently",
        case.case_id
    );

    // The export directory must still be there, or the harness below cannot
    // find `GetAppVersion` / `Run` at all.
    const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
    let export_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    assert_ne!(
        export_dir.virtual_address, 0,
        "[{}] product has no export directory",
        case.case_id
    );

    // ---- 5b. the exception table must hold real entries ----
    //
    // This is the assertion that catches the defect this gate found: `.pdata`
    // used to be 50376 bytes of **pure zeroes** because the table was read from
    // the dump buffer at an RVA that the shrink had already compacted away.
    // A product with a zero `.pdata` still loads and still reaches its window —
    // which is why the behavioural checks below cannot see it — but every
    // exception raised inside it would find no unwind entry.
    //
    // Measured on the reference product: 4193 entries, all pointing inside the
    // sections it keeps.  An all-zero table has zero non-zero bytes; a real one
    // has ~37k.
    const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
    let exc_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    assert_ne!(
        exc_dir.virtual_address, 0,
        "[{}] product has no exception directory — `.pdata` was dropped",
        case.case_id
    );
    assert!(
        exc_dir.size >= 12 && exc_dir.size % 12 == 0,
        "[{}] exception directory size {} is not a whole number of \
         RUNTIME_FUNCTION entries",
        case.case_id,
        exc_dir.size
    );

    let exc_bytes = read_dir_bytes(&out_dll, exc_dir.virtual_address, exc_dir.size)
        .unwrap_or_else(|| panic!("[{}] cannot read the exception table", case.case_id));
    let non_zero = exc_bytes.iter().filter(|b| **b != 0).count();
    assert!(
        non_zero * 2 > exc_bytes.len(),
        "[{}] exception table is mostly zeroes ({} of {} bytes) — it was \
         zero-filled instead of captured from live memory",
        case.case_id,
        non_zero,
        exc_bytes.len()
    );

    // Every entry must describe code the product actually has.  An entry that
    // points outside the image is worse than no entry: an unwinder would chase
    // it into unmapped memory.
    let sections: Vec<(u32, u32)> = pe
        .sections
        .iter()
        .map(|s| (s.virtual_address, s.virtual_address.saturating_add(s.virtual_size)))
        .collect();
    let inside = |v: u32| sections.iter().any(|&(lo, hi)| v >= lo && v < hi);
    let mut entries = 0usize;
    let mut outside = 0usize;
    let mut unsorted = 0usize;
    let mut prev = 0u32;
    for chunk in exc_bytes.chunks_exact(12) {
        let begin = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let end = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let unwind = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);
        entries += 1;
        if begin < prev {
            unsorted += 1;
        }
        prev = begin;
        if !inside(begin) || !inside(end) || !inside(unwind) {
            outside += 1;
        }
    }
    assert_eq!(
        outside, 0,
        "[{}] {entries} exception entries, {outside} point outside the product's \
         own sections",
        case.case_id
    );
    assert_eq!(
        unsorted, 0,
        "[{}] exception table is not sorted by BeginAddress — \
         RtlLookupFunctionEntry binary-searches it",
        case.case_id
    );
    println!(
        "[{}] exception table: {entries} entries, all inside the image, sorted",
        case.case_id
    );

    // ---- 6. byte-level reproducibility (skipped when the case says so) ----
    if !case.expect_output_sha256.is_empty() && case.expect_output_sha256 != "none" {
        assert_eq!(
            sha256_of(&out_dll),
            case.expect_output_sha256,
            "[{}] product SHA-256 drifted from the golden record",
            case.case_id
        );
    }

    // ---- 7. behaviour: version string + the window `Run()` creates ----
    //
    // This is the part that makes the case meaningful.  A product that loads
    // and exports correctly but answers `"0.0"` is the defect this gate exists
    // to catch, and no structural check above would notice it.
    let harness = build_harness(&out_dir);
    let run = Command::new(&harness)
        .arg(&out_dll)
        .output()
        .unwrap_or_else(|e| panic!("[{}] cannot run harness: {e}", case.case_id));

    let hlog = String::from_utf8_lossy(&run.stdout).to_string()
        + &String::from_utf8_lossy(&run.stderr);
    let hlog_path = out_dir.join("harness.log");
    std::fs::write(&hlog_path, &hlog).ok();

    let field = |key: &str| -> Option<String> {
        hlog.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .map(str::to_string)
    };

    assert_eq!(
        field("LOADED").as_deref(),
        Some("1"),
        "[{}] product does not load (harness log: {})\n{}",
        case.case_id,
        hlog_path.display(),
        hlog
    );

    assert_eq!(
        field("VERSION").as_deref(),
        Some(case.expect_version.as_str()),
        "[{}] GetAppVersion() regressed — the shell's initialisation was not \
         captured before the dump (harness log: {})\n{}",
        case.case_id,
        hlog_path.display(),
        hlog
    );

    assert_eq!(
        field("WINDOW_FOUND").as_deref(),
        Some("1"),
        "[{}] the product never created its window — Run() did not get going \
         (harness log: {})\n{}",
        case.case_id,
        hlog_path.display(),
        hlog
    );

    assert_eq!(
        field("WINDOW_CLASS").as_deref(),
        Some(case.expect_window_class.as_str()),
        "[{}] window class changed (harness log: {})\n{}",
        case.case_id,
        hlog_path.display(),
        hlog
    );

    assert_eq!(
        field("WINDOW_TITLE").as_deref(),
        Some(case.expect_window_title.as_str()),
        "[{}] window title changed (harness log: {})\n{}",
        case.case_id,
        hlog_path.display(),
        hlog
    );

    // A visible window is the difference between "created" and "on screen".
    assert_eq!(
        field("WINDOW_VISIBLE").as_deref(),
        Some("1"),
        "[{}] window exists but is not visible (harness log: {})",
        case.case_id,
        hlog_path.display()
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}

// ---------------------------------------------------------------------------
// Log scraping helpers
// ---------------------------------------------------------------------------

/// `IAT trace complete: {resolved} resolved, {failed} failed`
fn extract_trace_counts(log: &str) -> Option<(usize, usize)> {
    let line = log
        .lines()
        .rev()
        .find(|l| l.contains("IAT trace complete: "))?;
    let rest = line.split_once("IAT trace complete: ")?.1;
    let resolved: usize = rest.split_whitespace().next()?.parse().ok()?;
    let failed: usize = rest
        .split_once("resolved, ")?
        .1
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((resolved, failed))
}

/// `IAT trace complete: {r} resolved, {f} failed, {n} not-an-import`
fn extract_not_import(log: &str) -> Option<usize> {
    let line = log.lines().rev().find(|l| l.contains("IAT trace complete: "))?;
    let rest = line.split_once("not-an-import")?.0;
    let tail = rest.rsplit_once("failed, ")?.1;
    tail.trim().parse().ok()
}

/// `IAT boundaries: ... size=26264 (3283 slots), ...`
fn extract_iat_slots(log: &str) -> Option<usize> {
    let line = log.lines().rev().find(|l| l.contains("IAT boundaries:"))?;
    let rest = line.split_once("slots)")?.0;
    let n = rest.rsplit_once('(')?.1;
    n.trim().parse().ok()
}

// ---------------------------------------------------------------------------
// Self-tests for the scrapers and the manifest
// ---------------------------------------------------------------------------

#[test]
fn trace_count_scraper_parses_real_lines() {
    let log = "[INFO] [v3-trace] OK IAT trace complete: 289 resolved, 3 failed\n";
    assert_eq!(extract_trace_counts(log), Some((289, 3)));
}

#[test]
fn trace_count_scraper_returns_none_without_marker() {
    assert_eq!(extract_trace_counts("[INFO] something else\n"), None);
}

#[test]
fn not_import_scraper_parses_real_lines() {
    let log = "[INFO] [v3-trace] OK IAT trace complete: 289 resolved, 0 failed, 3 not-an-import\n";
    assert_eq!(extract_not_import(log), Some(3));
}

#[test]
fn not_import_scraper_returns_none_without_marker() {
    assert_eq!(extract_not_import("[INFO] 289 resolved, 0 failed\n"), None);
}

#[test]
fn iat_slot_scraper_parses_real_lines() {
    let log = "[INFO] IAT boundaries: start=0x7fffe1321a80, end=0x7fffe1328118, \
               size=26264 (3283 slots), blocks=17\n";
    assert_eq!(extract_iat_slots(log), Some(3283));
}

#[test]
fn iat_slot_scraper_returns_none_without_marker() {
    assert_eq!(extract_iat_slots("[INFO] no boundaries here\n"), None);
}

#[test]
fn manifest_is_present_and_well_formed() {
    let case = load_manifest(&manifest_path());
    assert_eq!(case.case_id, "core_dll");
    assert_eq!(case.sample_sha256.len(), 64);
    assert!(case.expect_resolved > 0);
    assert!(!case.expect_version.is_empty());
    assert!(!case.expect_window_class.is_empty());
    // This case became byte-reproducible once `__security_cookie` was zeroed at
    // dump time, so it now records a real hash.  `none` would mean the
    // nondeterminism came back — see the manifest header for the reasoning.
    assert_eq!(
        case.expect_output_sha256.len(),
        64,
        "core_dll is byte-reproducible now; record its SHA-256, or investigate \
         why the product became nondeterministic again"
    );
}
