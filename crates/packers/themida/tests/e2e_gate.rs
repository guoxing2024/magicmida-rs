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
    /// Characteristics the product's **first** section must declare.
    ///
    /// This is a fidelity assertion, not a cosmetic one.  The dump used to grant
    /// `IMAGE_SCN_MEM_WRITE` to the first section unconditionally, so the
    /// product claimed `.text` was writable (`0xe0000020`) while the reference
    /// declares read-execute (`0x60000020`).  A writable `.text` is the
    /// signature packers leave behind, and anti-cheat / integrity checks look
    /// for exactly that — a dump is supposed to describe the original layout.
    ///
    /// The bit was never load-bearing: hand-patching the product to
    /// `0x60000020` changes one byte and behaviour is identical.
    expect_first_section_characteristics: u32,
    /// Title of the licence dialog the product shows once it is really running.
    ///
    /// Optional: when empty the gate falls back to plain liveness.  When set, it
    /// is used both as the product's success signal and as the *control* signal
    /// (see `classify_gui`) — the original packed sample is run alongside the
    /// product so an unavailable remote dependency cannot be mistaken for an
    /// unpack failure.
    expect_window_title: String,
}

/// Parse the tiny key/value manifest format used by this directory.
///
/// Deliberately not serde: adding a dependency for a test fixture is not worth
/// it, and a hand-rolled parser keeps the file readable in review.
fn load_manifest(path: &Path) -> CaseManifest {
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
        let raw = get(key);
        // Accept `0x` hex as well as decimal: the manifest records section
        // characteristics, and writing `60000020` in decimal would be
        // unreadable next to the reference's `0x60000020`.
        let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            usize::from_str_radix(hex, 16)
        } else {
            raw.parse()
        };
        parsed.unwrap_or_else(|e| panic!("manifest key `{key}` is not a number: {e}"))
    };
    // Optional key: absent means "not declared", not "malformed".
    let opt = |key: &str| -> Option<String> {
        text.lines()
            .map(str::trim)
            .find(|l| !l.starts_with('#') && l.split(':').next() == Some(key))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
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
    let expect_first_section_characteristics = num("expect_first_section_characteristics") as u32;
    let expect_window_title = opt("expect_window_title").unwrap_or_default();

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
        expect_first_section_characteristics,
        expect_window_title,
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
///
/// The pipeline goldens were recorded with a **release** build (the RUNBOOK's
/// documented run path), and the debug build's timing is a different animal
/// entirely (measured on the DLL gate 2026-10-26: debug reproducibly loses the
/// shell's main thread before the IAT trace).  `cargo test` without
/// `--release` puts this test binary in `target/<profile>/deps`, so prefer the
/// same target triple's release binary and fall back to the test's own profile
/// only when release was never built.
fn mida_cli_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let profile_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("test exe lives in target/<profile>/deps")
        .to_path_buf();
    let base = profile_dir
        .parent()
        .expect("profile dir has a parent")
        .to_path_buf();
    let release = base.join("release").join("mida-cli.exe");
    if release.is_file() {
        return release;
    }
    let same_profile = profile_dir.join("mida-cli.exe");
    assert!(
        same_profile.exists(),
        "mida-cli.exe not found at {} (or {}) — build it first: cargo build --release -p mida-cli",
        release.display(),
        same_profile.display()
    );
    println!(
        "note: no release mida-cli.exe under {}, falling back to {}",
        base.display(),
        same_profile.display()
    );
    same_profile
}

// ---------------------------------------------------------------------------
// Launch observation and classification
// ---------------------------------------------------------------------------
//
// # Why this is not just "is the process still alive?"
//
// The old criterion was liveness at a deadline.  That is a proxy for "the
// product reached its GUI", and it silently folds in a second, unrelated
// question: does the product need anything from outside the machine?
//
// The reference sample does.  It fetches a module from a remote server before
// showing its licence dialog.  Measured while the server was unreachable: the
// *original packed sample* — the one this whole project is validated against —
// never creates its licence window either; it shows a `程序启动` message box
// reading "无法获取程序模块，请检查网络后重试" and then exits 0 after ~14.5 s.
// Under the old criterion that run was reported as "product did not reach its
// message loop — dump is not loadable", i.e. a false accusation against a dump
// whose bytes match the golden record exactly.
//
// The fix is to stop guessing and start comparing: run the **original sample**
// as a control alongside the product, in the same environment, and ask whether
// the control could reach the licence dialog.  That separates the two failure
// modes cleanly:
//
//   control reaches licence + product reaches licence  -> GUI works
//   control reaches licence + product does not         -> the product is at fault
//   control does not reach licence                     -> the environment cannot
//                                                         run this sample at all;
//                                                         this check is not exercised
//
// The third case does not silently pass: the product must still not crash, and
// the attempt prints everything it observed so the limitation is visible rather
// than inferred.

/// What was observed while a process was running.
#[derive(Debug, Clone, Default)]
struct LaunchObservation {
    /// Titles of top-level windows owned by the process, deduplicated.
    titles: Vec<String>,
    /// True when at least one *visible* top-level window was seen.
    saw_visible_window: bool,
    /// How many samples saw any window at all.
    window_samples: usize,
    /// Exit code when the process left on its own before the deadline.
    exit_code: Option<u32>,
    /// Milliseconds between spawn and that exit.
    exit_after_ms: u64,
    /// True when it was still running at the deadline.
    alive_at_deadline: bool,
}

impl LaunchObservation {
    /// True when a window whose title contains `needle` was seen.
    fn saw_title(&self, needle: &str) -> bool {
        let needle = needle.trim();
        !needle.is_empty() && self.titles.iter().any(|t| t.contains(needle))
    }

    /// True when the process neither crashed nor was killed by us.
    ///
    /// A structurally broken dump typically dies with a non-zero code during
    /// loader or CRT initialisation, so this still has discriminating power even
    /// when the licence dialog cannot be reached.
    fn exited_cleanly_or_alive(&self) -> bool {
        match self.exit_code {
            None => true,
            Some(0) => true,
            Some(_) => false,
        }
    }

    /// One-line evidence string for failure messages.
    fn describe(&self) -> String {
        let outcome = if self.alive_at_deadline {
            "still alive at the deadline".to_string()
        } else {
            format!(
                "exited code={} after {}ms",
                self.exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "?".into()),
                self.exit_after_ms
            )
        };
        let titles = if self.titles.is_empty() {
            "no top-level windows".to_string()
        } else {
            format!("windows: {}", self.titles.join(" | "))
        };
        format!("{outcome}; {titles}")
    }
}

/// How the GUI half of the gate came out.
#[derive(Debug, PartialEq, Eq)]
enum GuiVerdict {
    /// The licence dialog appeared in the product.
    ProductReachedGui,
    /// The control reached the licence dialog but the product did not, so the
    /// environment is demonstrably able to run this sample: the product is at
    /// fault.  This is the only verdict that accuses the dump.
    ProductSideDefect,
    /// The control could not reach the licence dialog either, so the sample's
    /// remote dependency is unavailable and the GUI assertion cannot be
    /// exercised.  Not a verdict about the dump.
    EnvironmentNotHealthy,
}

/// Decide the GUI verdict from the two observations.
///
/// Pure function on purpose: it is the part that can be wrong in a way that
/// produces false alarms, so it is unit-tested against synthetic observations
/// without launching anything.
fn classify_gui(
    control: &LaunchObservation,
    product: &LaunchObservation,
    licence_title: &str,
) -> GuiVerdict {
    if licence_title.trim().is_empty() {
        // No declared GUI signal: fall back to the historical liveness rule.
        return if product.alive_at_deadline || product.saw_visible_window {
            GuiVerdict::ProductReachedGui
        } else {
            GuiVerdict::ProductSideDefect
        };
    }
    let control_ok = control.saw_title(licence_title);
    let product_ok = product.saw_title(licence_title);
    match (control_ok, product_ok) {
        (true, true) => GuiVerdict::ProductReachedGui,
        (true, false) => GuiVerdict::ProductSideDefect,
        (false, _) => GuiVerdict::EnvironmentNotHealthy,
    }
}

/// Spawn `exe`, watch it for `budget`, and report what was observed.
///
/// Polls fast (10 ms by default): the product's whole startup can be shorter
/// than a coarse poll interval — measured 172 ms when its remote dependency is
/// unreachable — so a 250 ms poll can miss the entire run.
fn observe_launch(exe: &Path, budget: std::time::Duration) -> LaunchObservation {
    let mut obs = LaunchObservation::default();
    let mut child = match Command::new(exe)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("cannot launch {}: {e}", exe.display()),
    };
    let pid = child.id();
    let started = std::time::Instant::now();
    let poll = std::time::Duration::from_millis(10);

    let mut seen: Vec<String> = Vec::new();
    loop {
        let (titles, visible) = top_level_windows_of(pid);
        if !titles.is_empty() {
            obs.window_samples += 1;
        }
        if visible {
            obs.saw_visible_window = true;
        }
        for t in titles {
            if !seen.contains(&t) {
                seen.push(t);
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                obs.exit_code = status.code().map(|c| c as u32);
                obs.exit_after_ms = started.elapsed().as_millis() as u64;
                // One last sweep: a modal box may outlive the main thread.
                let (titles, visible) = top_level_windows_of(pid);
                if !titles.is_empty() {
                    obs.window_samples += 1;
                }
                if visible {
                    obs.saw_visible_window = true;
                }
                for t in titles {
                    if !seen.contains(&t) {
                        seen.push(t);
                    }
                }
                break;
            }
            Ok(None) => {}
            Err(e) => panic!("try_wait on {}: {e}", exe.display()),
        }

        if started.elapsed() >= budget {
            obs.alive_at_deadline = true;
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(poll);
    }

    obs.titles = seen;
    obs
}

/// Titles of top-level windows owned by `pid` (visible ones first-class).
///
/// Returns `(titles, saw_visible)`.  Titles are collected regardless of the
/// visibility flag so a dialog that is being created but not yet shown is still
/// recorded as evidence; `saw_visible` reports whether any was actually visible.
#[cfg(windows)]
fn top_level_windows_of(pid: u32) -> (Vec<String>, bool) {
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };

    struct Sink {
        pid: u32,
        titles: Vec<String>,
        saw_visible: bool,
    }

    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        // SAFETY: `lparam` carries the `&mut Sink` this call was started with,
        // and `EnumWindows` only invokes the callback during that call.
        let sink = unsafe { &mut *(lparam.0 as *mut Sink) };
        let mut owner = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner)) };
        if owner != sink.pid {
            return TRUE;
        }
        if unsafe { IsWindowVisible(hwnd) }.as_bool() {
            sink.saw_visible = true;
        }

        let mut class_buf = [0u16; 256];
        let mut title_buf = [0u16; 512];
        let cls_len = unsafe { GetClassNameW(hwnd, &mut class_buf) };
        let txt_len = unsafe { GetWindowTextW(hwnd, &mut title_buf) };
        let cls = String::from_utf16_lossy(&class_buf[..cls_len.max(0) as usize]);
        let txt = String::from_utf16_lossy(&title_buf[..txt_len.max(0) as usize]);

        // IME plumbing is owned by the process but says nothing about the
        // product, and would otherwise appear in every observation.
        let is_ime = cls == "IME" || cls == "MSCTFIME UI" || txt == "Default IME";
        if !is_ime && (!cls.is_empty() || !txt.is_empty()) {
            sink.titles.push(format!("{cls}/{txt}"));
        }
        TRUE
    }

    let mut sink = Sink {
        pid,
        titles: Vec::new(),
        saw_visible: false,
    };
    let ptr = &mut sink as *mut Sink;
    // SAFETY: `EnumWindows` invokes the callback synchronously, and `sink`
    // outlives the call.
    let _ = unsafe { EnumWindows(Some(callback), LPARAM(ptr as isize)) };
    (sink.titles, sink.saw_visible)
}

/// Non-Windows fallback so the file still compiles for `cargo check` elsewhere.
#[cfg(not(windows))]
fn top_level_windows_of(_pid: u32) -> (Vec<String>, bool) {
    (Vec::new(), false)
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

    // The first section must declare what the original declares.  A dump that
    // claims `.text` is writable is describing the packer's layout, not the
    // program's, and integrity checks key on exactly that bit.
    assert_eq!(
        pe.sections[0].characteristics,
        case.expect_first_section_characteristics,
        "[{}] first section characteristics are {:#010x}, expected {:#010x} — \
         a writable `.text` is the packer signature, not the original layout",
        case.case_id,
        pe.sections[0].characteristics,
        case.expect_first_section_characteristics
    );

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

    // ---- 8. did the product come up?  Ask the original, not just liveness ----
    //
    // See the `LaunchObservation` header for why liveness alone is not enough.
    // In short: the reference sample fetches a module from a remote server, so
    // "did not reach the message loop" can mean "this machine cannot run the
    // sample at all", which is not a statement about the dump.  The original
    // packed sample is run as a control to tell the two apart.
    //
    // Leftover instances are killed first.  The product is a single-instance
    // licence dialog: a survivor from a previous run makes the *new* instance
    // exit immediately, which under the old criterion was reported as "dump is
    // not loadable" for a perfectly good dump (measured: roughly 1 run in 5).
    for stem in [
        out_exe.file_stem().and_then(|s| s.to_str()).unwrap_or(""),
        case.sample_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(""),
    ] {
        if stem.is_empty() {
            continue;
        }
        let _ = Command::new("taskkill")
            .args(["/IM", &format!("{stem}.exe"), "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    let budget = std::time::Duration::from_secs(20);

    // The control: the original packed sample, same environment, same machine.
    let control = observe_launch(&case.sample_path, budget);
    eprintln!("[{}] control (original): {}", case.case_id, control.describe());

    // The product, with one retry.  A *single* non-successful launch is not
    // conclusive: residual contention right after the unpack run (ScyllaHide
    // injector and debuggee teardown are asynchronous) can make the first
    // attempt exit early even though every structural and byte-level check
    // passed on the same file.
    let mut product = observe_launch(&out_exe, budget);
    let mut verdict = classify_gui(&control, &product, &case.expect_window_title);
    if verdict == GuiVerdict::ProductSideDefect {
        eprintln!(
            "[{}] product attempt 1 did not come up ({}); retrying once",
            case.case_id,
            product.describe()
        );
        std::thread::sleep(std::time::Duration::from_secs(2));
        product = observe_launch(&out_exe, budget);
        verdict = classify_gui(&control, &product, &case.expect_window_title);
    }
    eprintln!("[{}] product: {}", case.case_id, product.describe());

    match verdict {
        GuiVerdict::ProductReachedGui => {
            eprintln!(
                "[{}] GUI check: product showed `{}` (control agreed)",
                case.case_id, case.expect_window_title
            );
        }
        GuiVerdict::ProductSideDefect => {
            panic!(
                "[{}] the control reached the licence dialog but the product did not — \
                 this is a dump-side defect, not an environment problem.\n  \
                 licence title looked for: `{}`\n  control (original): {}\n  \
                 product: {}\n  (log: {})",
                case.case_id,
                case.expect_window_title,
                control.describe(),
                product.describe(),
                log_path.display()
            );
        }
        GuiVerdict::EnvironmentNotHealthy => {
            // The sample cannot run here, so the GUI assertion is not
            // exercised.  Do not accuse the dump — but do not silently pass
            // either: a dump that crashes is still caught, and the whole
            // observation is printed so the limitation is visible.
            assert!(
                product.exited_cleanly_or_alive(),
                "[{}] the control could not reach its licence dialog (`{}`), so that \
                 check cannot run — but the product also crashed, which is a dump-side \
                 failure on its own.\n  control (original): {}\n  product: {}\n  \
                 (log: {})",
                case.case_id,
                case.expect_window_title,
                control.describe(),
                product.describe(),
                log_path.display()
            );
            eprintln!(
                "[{}] WARNING: GUI check NOT exercised — the original packed sample \
                 could not reach `{}` on this machine either, so the sample's remote \
                 dependency is unavailable.  Byte-level and structural checks above \
                 still passed.  control: {}",
                case.case_id,
                case.expect_window_title,
                control.describe()
            );
        }
    }

    let _ = std::fs::remove_dir_all(&out_dir);
}

// ---------------------------------------------------------------------------
// Log scraping helpers
// ---------------------------------------------------------------------------

/// `IAT trace complete: {resolved} resolved, {failed} failed`
fn extract_usize(log: &str, marker: &str) -> Option<(usize, usize)> {
    let clean = strip_ansi(log);
    let line = clean.lines().rev().find(|l| l.contains(marker))?;
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

/// Tracing renders structured fields with ANSI word-wrapping
/// (`[3mname[0m[2m=[0m`), which breaks plain-substring
/// scraping of `key=value` lines.  Strip the escapes first — the logs are
/// data here, not display.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn extract_pair(log: &str, marker: &str) -> Option<(usize, usize)> {
    let clean = strip_ansi(log);
    let line = clean.lines().rev().find(|l| l.contains(marker))?;
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
    let clean = strip_ansi(log);
    let line = clean.lines().rev().find(|l| l.contains("IAT boundaries:"))?;
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
    assert!(
        !case.expect_window_title.is_empty(),
        "the EXE case must declare the licence dialog title, otherwise the GUI \
         check degrades to liveness and the external-dependency false alarm \
         comes back"
    );
    // The fidelity assertion must encode the *reference's* flags, not the old
    // product's.  `0xe0000020` is what a packer leaves behind; accepting it as
    // the goal would make the gate assert the defect it exists to catch.
    assert_eq!(
        case.expect_first_section_characteristics, 0x6000_0020,
        "the reference declares read-execute `.text`; a writable-text \
         expectation would encode the packer signature as the goal"
    );
}

// ---------------------------------------------------------------------------
// GUI classification: the part that decides whether to accuse the dump
// ---------------------------------------------------------------------------
//
// These are the tests that matter for the false-alarm fix, and they need no
// sample, no Windows and no launching — they are pure functions of what an
// observation reported.

/// Build an observation that saw a window with the given title.
fn obs_with_title(title: &str) -> LaunchObservation {
    LaunchObservation {
        titles: vec![format!("SomeClass/{title}")],
        saw_visible_window: true,
        window_samples: 1,
        exit_code: None,
        exit_after_ms: 0,
        alive_at_deadline: true,
    }
}

/// Build an observation of a process that left cleanly without a window —
/// exactly what the product does when its remote dependency is unreachable.
fn obs_clean_exit_no_window() -> LaunchObservation {
    LaunchObservation {
        titles: Vec::new(),
        saw_visible_window: false,
        window_samples: 0,
        exit_code: Some(0),
        exit_after_ms: 172,
        alive_at_deadline: false,
    }
}

#[test]
fn both_reaching_the_dialog_is_a_pass() {
    let c = obs_with_title("授权验证");
    let p = obs_with_title("授权验证");
    assert_eq!(
        classify_gui(&c, &p, "授权验证"),
        GuiVerdict::ProductReachedGui
    );
}

#[test]
fn control_healthy_and_product_silent_accuses_the_dump() {
    // The environment can run this sample (the control got there), so the
    // product's silence is the product's fault.  This is the only case that
    // should ever produce "dump is not loadable".
    let c = obs_with_title("授权验证");
    let p = obs_clean_exit_no_window();
    assert_eq!(
        classify_gui(&c, &p, "授权验证"),
        GuiVerdict::ProductSideDefect
    );
}

#[test]
fn control_also_failing_is_environmental_not_a_dump_defect() {
    // Measured case: the remote module server is unreachable, so the ORIGINAL
    // sample cannot reach its dialog either.  The product's silence proves
    // nothing about the dump.
    let c = obs_clean_exit_no_window();
    let p = obs_clean_exit_no_window();
    assert_eq!(
        classify_gui(&c, &p, "授权验证"),
        GuiVerdict::EnvironmentNotHealthy
    );
}

#[test]
fn environmental_is_decided_by_the_control_alone() {
    // Even if the product *does* come up, a control that cannot come up means
    // this check was not exercised — the verdict must not flip to a pass that
    // pretends the GUI was verified.
    let c = obs_clean_exit_no_window();
    let p = obs_with_title("授权验证");
    assert_eq!(
        classify_gui(&c, &p, "授权验证"),
        GuiVerdict::EnvironmentNotHealthy
    );
}

#[test]
fn a_nonzero_exit_is_still_a_failure_while_the_environment_is_down() {
    // The environmental branch must not become a blanket pass: a dump that
    // crashes is caught regardless of what the control managed to do.
    let crash = LaunchObservation {
        titles: Vec::new(),
        saw_visible_window: false,
        window_samples: 0,
        exit_code: Some(0xC000_0005),
        exit_after_ms: 40,
        alive_at_deadline: false,
    };
    assert!(!crash.exited_cleanly_or_alive());
    assert!(obs_clean_exit_no_window().exited_cleanly_or_alive());
    assert!(obs_with_title("授权验证").exited_cleanly_or_alive());
}

#[test]
fn a_wrong_licence_title_cannot_by_itself_condemn_the_product() {
    // If the manifest's title is wrong, the control cannot match it either, so
    // the outcome must be "not exercised" rather than "product at fault".
    let c = obs_with_title("授权验证");
    let p = obs_with_title("授权验证");
    assert_eq!(
        classify_gui(&c, &p, "SomeOtherTitle"),
        GuiVerdict::EnvironmentNotHealthy
    );
}

#[test]
fn without_a_declared_title_the_old_liveness_rule_still_applies() {
    let alive = obs_with_title("授权验证");
    let dead = obs_clean_exit_no_window();
    assert_eq!(
        classify_gui(&dead, &alive, ""),
        GuiVerdict::ProductReachedGui
    );
    assert_eq!(
        classify_gui(&alive, &dead, ""),
        GuiVerdict::ProductSideDefect
    );
}

#[test]
fn titles_are_matched_by_substring_not_equality() {
    // The observed title can carry decoration; matching must not be brittle.
    let p = LaunchObservation {
        titles: vec!["#32770/授权验证 - 请注册".to_string()],
        saw_visible_window: true,
        window_samples: 1,
        exit_code: None,
        exit_after_ms: 0,
        alive_at_deadline: true,
    };
    assert!(p.saw_title("授权验证"));
    assert!(!p.saw_title("程序启动"));
}

#[test]
fn describe_reports_the_evidence_needed_to_diagnose_a_failure() {
    let cleaned = obs_clean_exit_no_window().describe();
    assert!(cleaned.contains("code=0"), "{cleaned}");
    assert!(cleaned.contains("no top-level windows"), "{cleaned}");

    let dialogs = obs_with_title("授权验证").describe();
    assert!(dialogs.contains("still alive"), "{dialogs}");
    assert!(dialogs.contains("授权验证"), "{dialogs}");
}
