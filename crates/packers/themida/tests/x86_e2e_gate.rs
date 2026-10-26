//! End-to-end acceptance gate for the reference Themida v3 **x86 (PE32)** case.
//!
//! # Why a fifth gate
//!
//! `e2e_gate.rs` covers the x64 EXE, `dll_e2e_gate.rs` the x64 DLL.  Both are
//! 64-bit, and the 32-bit path fails in ways 64-bit code cannot: 32-bit x86 has
//! no RIP-relative addressing, so every global access in the image is an
//! absolute operand that has to be relocated; `.text` operands are invisible to
//! a byte-stride scan; and the loader's treatment of an uninitialised section is
//! the difference between a product that starts and one that never shows a
//! window.  This gate pins all of that.
//!
//! # Both criteria, because both were measured to hold
//!
//! The x64 EXE case records a hash but classifies its GUI outcome against a
//! control, because that sample fetches a module over the network and the check
//! cannot always be exercised.  This sample has no such dependency — it is a
//! local test program — so there is nothing that could be unavailable except the
//! desktop session.  The GUI assertion is therefore **hard**, and the byte
//! assertion is hard too: measured 4/4 independent runs, all identical.
//!
//! # Running it
//!
//! ```text
//! cargo test --release --target i686-pc-windows-gnu \
//!     -p mida-packers-themida --test x86_e2e_gate -- --ignored --nocapture
//! ```
//!
//! The test binary must be 32-bit, and `mida-cli-x86.exe` must sit next to the
//! 64-bit `mida-cli.exe`: the debugger's register layout follows the *host*, so
//! a 64-bit `mida-cli` refuses a 32-bit target outright.  Needs the sample, the
//! ScyllaHide x86 helpers, and — for the last assertion — an interactive desktop
//! session.

use std::path::{Path, PathBuf};
use std::process::Command;

use mida_pe::PeHeader;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Case manifest
// ---------------------------------------------------------------------------

/// The subset of the case manifest this gate needs.
#[derive(Debug)]
struct X86Case {
    case_id: String,
    sample_path: PathBuf,
    sample_sha256: String,
    sample_size: u64,
    reference_path: PathBuf,
    reference_sha256: String,
    reference_size: u64,
    expect_resolved: usize,
    expect_failed: usize,
    expect_not_import: usize,
    expect_iat_slots_min: usize,
    expect_module_count: usize,
    expect_thunk_count: usize,
    expect_relocation_entries: usize,
    expect_relocation_bytes: usize,
    expect_code_relocations: usize,
    expect_relocation_blocks: usize,
    expect_relocation_table_entries: usize,
    expect_output_size: u64,
    expect_output_sha256: String,
    expect_is_64bit: bool,
    expect_section_count: usize,
    expect_entry_point: u32,
    expect_first_section_characteristics: u32,
    expect_image_base: u64,
    expect_window_class: String,
    expect_window_title: String,
}

fn load_manifest(path: &Path) -> X86Case {
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
    let num = |key: &str| -> u64 {
        let raw = get(key);
        // Accept both plain decimal and `0x`-prefixed hex: the structural
        // expectations are far easier to read in hex.
        let parsed = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => raw.parse::<u64>(),
        };
        parsed.unwrap_or_else(|e| panic!("manifest key `{key}` is not a number: {e}"))
    };
    let usize_of = |key: &str| num(key) as usize;

    X86Case {
        case_id: get("case_id"),
        sample_path: PathBuf::from(get("sample_path")),
        sample_sha256: get("sample_sha256").to_lowercase(),
        sample_size: num("sample_size"),
        reference_path: PathBuf::from(get("reference_path")),
        reference_sha256: get("reference_sha256").to_lowercase(),
        reference_size: num("reference_size"),
        expect_resolved: usize_of("expect_resolved"),
        expect_failed: usize_of("expect_failed"),
        expect_not_import: usize_of("expect_not_import"),
        expect_iat_slots_min: usize_of("expect_iat_slots_min"),
        expect_module_count: usize_of("expect_module_count"),
        expect_thunk_count: usize_of("expect_thunk_count"),
        expect_relocation_entries: usize_of("expect_relocation_entries"),
        expect_relocation_bytes: usize_of("expect_relocation_bytes"),
        expect_code_relocations: usize_of("expect_code_relocations"),
        expect_relocation_blocks: usize_of("expect_relocation_blocks"),
        expect_relocation_table_entries: usize_of("expect_relocation_table_entries"),
        expect_output_size: num("expect_output_size"),
        expect_output_sha256: get("expect_output_sha256").to_lowercase(),
        expect_is_64bit: get("expect_is_64bit") == "true",
        expect_section_count: usize_of("expect_section_count"),
        expect_entry_point: num("expect_entry_point") as u32,
        expect_first_section_characteristics: num("expect_first_section_characteristics") as u32,
        expect_image_base: num("expect_image_base"),
        expect_window_class: get("expect_window_class"),
        expect_window_title: get("expect_window_title"),
    }
}

fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases/x86_sample.case")
}

fn sha256_of(path: &Path) -> String {
    let data = std::fs::read(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut h = Sha256::new();
    h.update(&data);
    format!("{:x}", h.finalize())
}

/// Locate a **32-bit** CLI that belongs to this test run.
///
/// `mida-cli.exe` is the 64-bit build and refuses a 32-bit target: the
/// debugger's register layout follows the host.  So the candidate list is
/// checked against each binary's own PE header rather than trusted by name —
/// under the i686 target, `<target-dir>/release/mida-cli.exe` *is* the 32-bit
/// build, while under the x64 target it is the 64-bit one.
///
/// Failing with the exact build commands matters: the CLI's own message
/// ("please use the 32-bit version of Magicmida") reads like a tool defect when
/// it is really a missing build step.
fn mida_cli_x86_path() -> PathBuf {
    let mut dir = std::env::current_exe().expect("current_exe");
    dir.pop(); // deps/
    dir.pop(); // <profile>/  (…/target/<triple>/release or …/target/release)

    let mut candidates: Vec<PathBuf> = Vec::new();
    // Same directory as the test binary: under the i686 target this is already
    // the 32-bit build.
    candidates.push(dir.join("mida-cli.exe"));
    candidates.push(dir.join("mida-cli-x86.exe"));
    // The x64 target's release dir, where the 32-bit build is installed under a
    // distinct name so both can coexist.
    if let Some(target_dir) = dir.parent().and_then(|p| p.parent()) {
        candidates.push(target_dir.join("release").join("mida-cli-x86.exe"));
    }

    let checked: Vec<String> = candidates
        .iter()
        .map(|p| {
            let note = match PeHeader::from_file(p) {
                Ok(pe) if !pe.is_64bit => return format!("{} (PE32 — usable)", p.display()),
                Ok(_) => "PE32+ — cannot debug a 32-bit target",
                Err(_) => "missing or not a PE",
            };
            format!("{} ({note})", p.display())
        })
        .collect();

    for candidate in &candidates {
        if let Ok(pe) = PeHeader::from_file(candidate) {
            if !pe.is_64bit {
                return candidate.clone();
            }
        }
    }

    panic!(
        "no 32-bit mida-cli found — this gate needs one, because the debugger's \
         register layout follows the host and a 64-bit CLI refuses a 32-bit target.\n\
         Candidates checked:\n  {}\n\
         Build and install it with:\n  \
         cargo build --release --target i686-pc-windows-gnu -p mida-cli\n  \
         copy target\\i686-pc-windows-gnu\\release\\mida-cli.exe target\\release\\mida-cli-x86.exe",
        checked.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires the x86 sample, a 32-bit mida-cli, ScyllaHide x86 helpers, and a desktop session"]
fn e2e_x86_case_matches_golden_record() {
    let case = load_manifest(&manifest_path());

    // ---- 1. sample identity (fail-closed) ----
    assert!(
        case.sample_path.exists(),
        "[{}] sample not found at {}",
        case.case_id,
        case.sample_path.display()
    );
    assert_eq!(
        std::fs::metadata(&case.sample_path).unwrap().len(),
        case.sample_size,
        "[{}] sample size mismatch — refusing to run",
        case.case_id
    );
    assert_eq!(
        sha256_of(&case.sample_path),
        case.sample_sha256,
        "[{}] sample SHA-256 mismatch — refusing to run (identity is not a path)",
        case.case_id
    );

    // ---- 1b. the unpacked reference (cross-check only, never unpacked here) ----
    assert!(
        case.reference_path.exists(),
        "[{}] reference sample not found at {}",
        case.case_id,
        case.reference_path.display()
    );
    assert_eq!(
        std::fs::metadata(&case.reference_path).unwrap().len(),
        case.reference_size,
        "[{}] reference size mismatch",
        case.case_id
    );
    assert_eq!(
        sha256_of(&case.reference_path),
        case.reference_sha256,
        "[{}] reference SHA-256 mismatch",
        case.case_id
    );

    // ---- 2. run the real pipeline ----
    let cli = mida_cli_x86_path();
    let out_dir = std::env::temp_dir().join(format!("mida-x86-e2e-{}", std::process::id()));
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
    let log_path = out_dir.join("gate.log");
    std::fs::write(&log_path, &log).ok();

    assert_eq!(
        status, 0,
        "[{}] mida-cli-x86 exited {status}; log at {}",
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
        "[{}] not-an-import count changed — a slot is being misclassified as \
         data, or a real failure is hiding among them (log: {})",
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

    // ---- 5. IAT scan covered the whole table ----
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

    // ---- 6. the relocation table: the x86-specific half of this gate ----
    //
    // 32-bit x86 has no RIP-relative addressing, so every global access in the
    // image is an absolute operand and must be relocated.  The reference
    // sample's own table holds 277 entries, 256 of them inside `.text` — which
    // is exactly what a byte-stride scan cannot find and what an instruction
    // decoder can.
    let entries = extract_usize_after(&log, "Generated ").unwrap_or_else(|| {
        panic!(
            "[{}] no `Generated N relocation entries` line in log {}",
            case.case_id,
            log_path.display()
        )
    });
    assert_eq!(
        entries, case.expect_relocation_entries,
        "[{}] relocation entry count changed — the executable-section scan \
         regressed (log: {})",
        case.case_id,
        log_path.display()
    );

    // The 257 executable-section contributions are the part that cannot be
    // recovered any other way, so assert them by name rather than trusting the
    // total to imply them.  (The reference sample's own table holds 277 entries,
    // 256 of them in `.text`; this product's `.text` scan finds 257 because the
    // product carries one more absolute operand than the reference's table
    // records — the reference's table is the packed input's, not the product's.)
    let code_scan = extract_usize_after(&log, "absolute operands inside executable sections")
        .or_else(|| extract_usize_before(&log, " absolute operands inside executable sections"))
        .unwrap_or_else(|| {
            panic!(
                "[{}] no code-relocation scan line in log {} — the executable \
                 section scan did not run at all",
                case.case_id,
                log_path.display()
            )
        });
    assert_eq!(
        code_scan, case.expect_code_relocations,
        "[{}] executable-section operand scan found {code_scan} entries, expected \
         {} (log: {})",
        case.case_id,
        case.expect_code_relocations,
        log_path.display()
    );

    let reloc_bytes = extract_usize_after(&log, "Relocation table size: ").unwrap_or_else(|| {
        panic!(
            "[{}] no relocation table size line in log {}",
            case.case_id,
            log_path.display()
        )
    });
    assert_eq!(
        reloc_bytes, case.expect_relocation_bytes,
        "[{}] relocation table size changed (log: {})",
        case.case_id,
        log_path.display()
    );

    // ---- 7. product structure ----
    assert!(out_exe.exists(), "[{}] no product written", case.case_id);
    assert_eq!(
        std::fs::metadata(&out_exe).unwrap().len(),
        case.expect_output_size,
        "[{}] product size changed",
        case.case_id
    );

    let pe = PeHeader::from_file(&out_exe).expect("product must parse as PE");
    assert_eq!(
        pe.is_64bit, case.expect_is_64bit,
        "[{}] product has the wrong PE type — this case is PE32",
        case.case_id
    );
    assert_eq!(
        pe.sections.len(),
        case.expect_section_count,
        "[{}] section count changed",
        case.case_id
    );
    assert_eq!(
        pe.entry_point, case.expect_entry_point,
        "[{}] entry point moved",
        case.case_id
    );
    assert_eq!(
        pe.image_base, case.expect_image_base,
        "[{}] image base moved — every absolute operand in the image depends on it",
        case.case_id
    );

    // The first section must describe the *original* layout.  The historical
    // blanket rule produced `0xe0000020` (writable text) where the reference
    // declares `0x60000020`; a writable `.text` is what packers leave behind and
    // what integrity checks look for.
    let first = &pe.sections[0];
    assert_eq!(
        first.characteristics, case.expect_first_section_characteristics,
        "[{}] first section characteristics are {:#010x}, expected {:#010x} — \
         a writable `.text` is the packer signature, not the original layout",
        case.case_id,
        first.characteristics,
        case.expect_first_section_characteristics
    );

    // Every section must lie inside the declared image, and `.bss` must stay
    // uninitialised: giving it file bytes makes the loader stop zero-filling it,
    // and the captured shell state then becomes the program's initial state.
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
        const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
        if s.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            assert_eq!(
                s.raw_size, 0,
                "[{}] uninitialised section `{}` carries {} raw bytes — the \
                 loader would stop zero-filling it",
                case.case_id, s.name, s.raw_size
            );
        }
    }

    // The import directory must be populated.
    const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
    let import_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    assert_ne!(
        import_dir.virtual_address, 0,
        "[{}] product has no import directory — import rebuild failed silently",
        case.case_id
    );

    // The relocation directory must be populated too: this is the section the
    // x86 fix exists for, and a zeroed one would mean the table was built but
    // not published.
    const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
    let reloc_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    assert_ne!(
        reloc_dir.virtual_address, 0,
        "[{}] product has no base relocation directory",
        case.case_id
    );

    // ---- 7b. the relocation table that actually got written ----
    //
    // The log reports what was *requested* (295).  The table on disk holds a
    // slightly different number, because the builder also carries the entries
    // that already existed in the packed input and pads to whole 4-byte slots.
    // Asserting the log number alone would let a table that silently dropped
    // entries pass, so parse the directory.
    let table = parse_relocation_table(&out_exe, reloc_dir.virtual_address, reloc_dir.size)
        .unwrap_or_else(|| {
            panic!(
                "[{}] cannot parse the product's .reloc table at va {:#x} size {:#x}",
                case.case_id, reloc_dir.virtual_address, reloc_dir.size
            )
        });
    assert_eq!(
        table.blocks, case.expect_relocation_blocks,
        "[{}] relocation page-block count changed",
        case.case_id
    );
    assert_eq!(
        table.entries, case.expect_relocation_table_entries,
        "[{}] relocation entries in the table changed — the product would fail \
         to load at a different base (log: {})",
        case.case_id,
        log_path.display()
    );
    assert_eq!(
        table.bytes_consumed, reloc_dir.size as usize,
        "[{}] the relocation blocks consume {} bytes but the directory declares \
         {} — the table is truncated or padded inconsistently",
        case.case_id, table.bytes_consumed, reloc_dir.size
    );

    // Every entry must target a location the product actually has, and no entry
    // may land inside the import metadata — that was a real defect: relocating a
    // thunk's own bytes corrupts the names the loader reads.  Both are computed
    // inside `parse_relocation_table`, from the same section table, so they are
    // asserted there rather than recomputed here with a second, drifting copy of
    // the containment rule.
    assert_eq!(
        table.outside_image, 0,
        "[{}] {} of {} relocation entries point outside the product's sections",
        case.case_id, table.outside_image, table.entries
    );
    assert_eq!(
        table.in_import_metadata, 0,
        "[{}] {} relocation entries land inside import metadata — rebasing would \
         corrupt the names the loader reads (rebasing happens before imports are \
         resolved)",
        case.case_id, table.in_import_metadata
    );

    // ---- 8. byte-level reproducibility ----
    assert_eq!(
        sha256_of(&out_exe),
        case.expect_output_sha256,
        "[{}] product SHA-256 drifted from the golden record",
        case.case_id
    );

    // ---- 9. behaviour: the window the product creates ----
    //
    // A hard assertion, unlike the x64 EXE case: this sample has no remote
    // dependency, so nothing here can be unavailable except the desktop session
    // itself.
    kill_leftovers(&out_exe);
    kill_leftovers(&case.sample_path);
    std::thread::sleep(std::time::Duration::from_millis(300));

    let obs = observe_launch(&out_exe, std::time::Duration::from_secs(20));
    eprintln!("[{}] product: {}", case.case_id, obs.describe());

    assert!(
        obs.exited_cleanly_or_alive(),
        "[{}] the product crashed instead of running.\n  {}\n  (log: {})",
        case.case_id,
        obs.describe(),
        log_path.display()
    );
    assert!(
        obs.saw_class(&case.expect_window_class),
        "[{}] the product never created a `{}` window — the shell's \
         initialisation was not captured, or `.bss` was cleared when it should \
         have been kept.\n  {}\n  (log: {})",
        case.case_id,
        case.expect_window_class,
        obs.describe(),
        log_path.display()
    );
    assert!(
        obs.saw_title(&case.expect_window_title),
        "[{}] the window exists but its title changed.\n  {}\n  (log: {})",
        case.case_id,
        obs.describe(),
        log_path.display()
    );
    assert!(
        obs.saw_visible_window,
        "[{}] the window exists but was never visible.\n  {}",
        case.case_id,
        obs.describe()
    );

    eprintln!(
        "[{}] GUI check: product showed `{}` / `{}` in {} ms",
        case.case_id,
        case.expect_window_class,
        case.expect_window_title,
        obs.first_window_ms.unwrap_or(0)
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Kill leftover instances of an executable by stem.
///
/// The product is a single-window application; a survivor from a previous run
/// changes what the next launch observes.  The x64 gate learned this the hard
/// way (roughly 1 run in 5 produced a false accusation).
fn kill_leftovers(exe: &Path) {
    let Some(stem) = exe.file_stem().and_then(|s| s.to_str()) else {
        return;
    };
    let _ = Command::new("taskkill")
        .args(["/IM", &format!("{stem}.exe"), "/F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

// ---------------------------------------------------------------------------
// Relocation table parsing
// ---------------------------------------------------------------------------

/// What the product's own `.reloc` directory actually contains.
#[derive(Debug, Default, PartialEq, Eq)]
struct RelocTable {
    blocks: usize,
    entries: usize,
    /// Bytes the blocks consume, which must equal the directory's declared size.
    bytes_consumed: usize,
    /// Entries whose target RVA falls outside every section.
    outside_image: usize,
    /// Entries whose target RVA falls inside the import directory.
    in_import_metadata: usize,
}

/// Parse the base relocation table at `rva` in a PE file on disk.
///
/// Reads through the section table rather than assuming RVA == file offset: in a
/// *product* they happen to be equal (that is what `sanitize` establishes), but
/// relying on it would silently parse garbage the day that changes.
fn parse_relocation_table(path: &Path, rva: u32, size: u32) -> Option<RelocTable> {
    let data = std::fs::read(path).ok()?;
    let pe = PeHeader::from_file(path).ok()?;

    let to_offset = |rva: u32| -> Option<usize> {
        let sec = pe.sections.iter().find(|s| {
            rva >= s.virtual_address && rva < s.virtual_address.saturating_add(s.virtual_size.max(s.raw_size))
        })?;
        Some(sec.raw_offset as usize + (rva - sec.virtual_address) as usize)
    };

    let import_dir = pe.nt_headers.optional_header.data_directory[1];
    let import_lo = import_dir.virtual_address;
    let import_hi = import_lo.saturating_add(import_dir.size);

    let mut table = RelocTable::default();
    let mut pos = rva;
    let end = rva.checked_add(size)?;

    while pos < end {
        let off = to_offset(pos)?;
        let bytes = data.get(off..off.checked_add(8)?)?;
        let page = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let block_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if block_size < 8 || block_size % 4 != 0 {
            return None; // malformed; the caller reports it as unparseable
        }
        let count = (block_size as usize - 8) / 2;
        let entries_off = off.checked_add(8)?;
        let entries_bytes = data.get(entries_off..entries_off.checked_add(count * 2)?)?;

        table.blocks += 1;
        table.entries += count;
        table.bytes_consumed += block_size as usize;

        for chunk in entries_bytes.chunks_exact(2) {
            let word = u16::from_le_bytes([chunk[0], chunk[1]]);
            let kind = (word >> 12) as u32;
            let target = page.wrapping_add((word & 0x0FFF) as u32);
            // Type 0 is ABSOLUTE: padding, not a relocation.
            if kind == 0 {
                continue;
            }
            let in_any_section = pe.sections.iter().any(|s| {
                target >= s.virtual_address
                    && target < s.virtual_address.saturating_add(s.virtual_size.max(s.raw_size))
            });
            if !in_any_section {
                table.outside_image += 1;
            }
            if import_lo != 0 && target >= import_lo && target < import_hi {
                table.in_import_metadata += 1;
            }
        }

        pos = pos.checked_add(block_size)?;
    }

    Some(table)
}

// ---------------------------------------------------------------------------
// Launch observation
// ---------------------------------------------------------------------------

/// What was observed while the product was running.
#[derive(Debug, Clone, Default)]
struct LaunchObservation {
    /// `class/title` pairs of top-level windows owned by the process.
    windows: Vec<String>,
    /// True when at least one *visible* top-level window was seen.
    saw_visible_window: bool,
    /// Milliseconds from spawn to the first window of any kind.
    first_window_ms: Option<u64>,
    /// Exit code when the process left on its own before the deadline.
    exit_code: Option<u32>,
    /// Milliseconds between spawn and that exit.
    exit_after_ms: u64,
    /// True when it was still running at the deadline.
    alive_at_deadline: bool,
}

impl LaunchObservation {
    fn saw_title(&self, needle: &str) -> bool {
        let needle = needle.trim();
        !needle.is_empty() && self.windows.iter().any(|w| w.contains(needle))
    }

    /// Match on the class half specifically.
    ///
    /// The x64 gate only matches titles, which is enough for a licence dialog
    /// whose title is unique.  This sample's window class is the more stable
    /// identifier — the title is user-facing text and could be reworded — so it
    /// is matched as well.
    fn saw_class(&self, needle: &str) -> bool {
        let needle = needle.trim();
        !needle.is_empty()
            && self
                .windows
                .iter()
                .any(|w| w.split_once('/').map(|(c, _)| c) == Some(needle))
    }

    fn exited_cleanly_or_alive(&self) -> bool {
        match self.exit_code {
            None => true,
            Some(0) => true,
            Some(_) => false,
        }
    }

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
        let windows = if self.windows.is_empty() {
            "no top-level windows".to_string()
        } else {
            format!("windows: {}", self.windows.join(" | "))
        };
        format!("{outcome}; {windows}")
    }
}

/// Spawn `exe`, watch it for `budget`, and report what was observed.
///
/// Polls every 5 ms.  The measured first-window latency is **15 ms**, so a
/// 250 ms poll would be a coin flip and a 100 ms one would miss the useful
/// number entirely.
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
    let poll = std::time::Duration::from_millis(5);

    let mut seen: Vec<String> = Vec::new();
    loop {
        let (windows, visible) = top_level_windows_of(pid);
        if visible {
            obs.saw_visible_window = true;
        }
        if !windows.is_empty() && obs.first_window_ms.is_none() {
            obs.first_window_ms = Some(started.elapsed().as_millis() as u64);
        }
        for w in windows {
            if !seen.contains(&w) {
                seen.push(w);
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                obs.exit_code = status.code().map(|c| c as u32);
                obs.exit_after_ms = started.elapsed().as_millis() as u64;
                // One last sweep: a window may outlive the main thread.
                let (windows, visible) = top_level_windows_of(pid);
                if visible {
                    obs.saw_visible_window = true;
                }
                for w in windows {
                    if !seen.contains(&w) {
                        seen.push(w);
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

    obs.windows = seen;
    obs
}

/// `class/title` pairs of top-level windows owned by `pid`.
///
/// Titles are collected regardless of the visibility flag so a window that is
/// being created but not yet shown still counts as evidence; `saw_visible`
/// reports whether any was actually visible.
#[cfg(windows)]
fn top_level_windows_of(pid: u32) -> (Vec<String>, bool) {
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };

    struct Sink {
        pid: u32,
        windows: Vec<String>,
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
            sink.windows.push(format!("{cls}/{txt}"));
        }
        TRUE
    }

    let mut sink = Sink {
        pid,
        windows: Vec::new(),
        saw_visible: false,
    };
    let ptr = &mut sink as *mut Sink;
    // SAFETY: `EnumWindows` invokes the callback synchronously, and `sink`
    // outlives the call.
    let _ = unsafe { EnumWindows(Some(callback), LPARAM(ptr as isize)) };
    (sink.windows, sink.saw_visible)
}

#[cfg(not(windows))]
fn top_level_windows_of(_pid: u32) -> (Vec<String>, bool) {
    (Vec::new(), false)
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
    let line = log
        .lines()
        .rev()
        .find(|l| l.contains("IAT trace complete: "))?;
    let before = line.split_once("not-an-import")?.0;
    let tail = before.rsplit_once("failed, ")?.1;
    tail.trim().parse().ok()
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

/// `IAT boundaries: ... size=7860 (1965 slots), blocks=17`
fn extract_iat_slots(log: &str) -> Option<usize> {
    let clean = strip_ansi(log);
    let line = clean.lines().rev().find(|l| l.contains("IAT boundaries:"))?;
    let tail = line.split_once('(')?.1;
    tail.split_whitespace().next()?.parse().ok()
}

/// First integer appearing immediately after `marker` on the last line that
/// contains it.  Handles both `Generated 295 relocation entries` and
/// `Relocation table size: 692 bytes`.
fn extract_usize_after(log: &str, marker: &str) -> Option<usize> {
    let clean = strip_ansi(log);
    let line = clean.lines().rev().find(|l| l.contains(marker))?;
    let rest = line.split_once(marker)?.1;
    let token = rest
        .split_whitespace()
        .find(|t| t.chars().all(|c| c.is_ascii_digit()) && !t.is_empty())?;
    token.parse().ok()
}

/// First integer appearing immediately *before* `marker` on the last matching
/// line.  Handles `Code relocation scan (x86): 256 absolute operands …`, where
/// the number precedes the words that identify it.
fn extract_usize_before(log: &str, marker: &str) -> Option<usize> {
    let clean = strip_ansi(log);
    let line = clean.lines().rev().find(|l| l.contains(marker))?;
    let head = line.split_once(marker)?.0;
    head.split_whitespace()
        .rev()
        .find(|t| t.chars().all(|c| c.is_ascii_digit()) && !t.is_empty())?
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------
// Self-tests: these run in the normal suite, no sample needed
// ---------------------------------------------------------------------------

#[test]
fn trace_count_scraper_parses_the_real_x86_line() {
    let log = "[INFO] [v3-trace] OK IAT trace complete: 54 resolved, 0 failed, 54 not-an-import\n";
    assert_eq!(extract_trace_counts(log), Some((54, 0)));
    assert_eq!(extract_not_import(log), Some(54));
}

#[test]
fn import_table_scraper_parses_the_real_x86_line() {
    let log = "[INFO] Import table reconstructed module_count=4 thunk_count=54\n";
    assert_eq!(
        extract_pair(log, "Import table reconstructed module_count="),
        Some((4, 54))
    );
}

#[test]
fn iat_slot_scraper_parses_the_real_x86_line() {
    let log = "[INFO] IAT boundaries: start=0x40714c, end=0x409000, size=7860 (1965 slots), blocks=17\n";
    assert_eq!(extract_iat_slots(log), Some(1965));
}

#[test]
fn relocation_scrapers_parse_the_real_x86_lines() {
    let log = "\
[INFO] Generated 295 relocation entries
[INFO] Relocation table size: 692 bytes
[INFO] Code relocation scan (x86): 256 absolute operands inside executable sections
";
    assert_eq!(extract_usize_after(log, "Generated "), Some(295));
    assert_eq!(extract_usize_after(log, "Relocation table size: "), Some(692));
    assert_eq!(
        extract_usize_before(log, " absolute operands inside executable sections"),
        Some(256)
    );
}

#[test]
fn scrapers_return_none_on_missing_markers() {
    assert_eq!(extract_trace_counts("nothing here"), None);
    assert_eq!(extract_not_import("nothing here"), None);
    assert_eq!(extract_pair("nothing here", "module_count="), None);
    assert_eq!(extract_iat_slots("nothing here"), None);
    assert_eq!(extract_usize_after("nothing here", "Generated "), None);
    assert_eq!(extract_usize_before("nothing here", " absolute operands"), None);
}

#[test]
fn class_matching_is_on_the_class_half_only() {
    let obs = LaunchObservation {
        windows: vec!["MidaX86Sample/验证 x86 样本".to_string()],
        saw_visible_window: true,
        first_window_ms: Some(15),
        exit_code: None,
        exit_after_ms: 0,
        alive_at_deadline: true,
    };
    assert!(obs.saw_class("MidaX86Sample"));
    assert!(obs.saw_title("验证 x86 样本"));
    // `saw_title` is a substring match over the whole `class/title` pair, which
    // is deliberate: the observed title can carry decoration.  So the class name
    // *does* match it — what must not happen is a window whose class merely
    // equals some other window's title.
    assert!(obs.saw_title("MidaX86Sample"));
    let swapped = LaunchObservation {
        windows: vec!["验证 x86 样本/MidaX86Sample".to_string()],
        saw_visible_window: true,
        first_window_ms: Some(15),
        exit_code: None,
        exit_after_ms: 0,
        alive_at_deadline: true,
    };
    // The class half is where class matching looks, and it is exact.
    assert!(!swapped.saw_class("MidaX86Sample"));
    assert!(
        swapped.saw_class("验证 x86 样本"),
        "class matching reads the class half, which here holds the title text"
    );
}

#[test]
fn ime_windows_are_filtered_but_a_real_window_is_not() {
    // The filter itself lives in the Win32 callback, which needs a live
    // process; what is testable here is that the observation does not confuse
    // the two kinds once they have been recorded.
    let only_ime = LaunchObservation {
        windows: vec!["IME/Default IME".to_string(), "MSCTFIME UI/MSCTFIME UI".to_string()],
        saw_visible_window: false,
        first_window_ms: Some(3),
        exit_code: None,
        exit_after_ms: 0,
        alive_at_deadline: true,
    };
    assert!(!only_ime.saw_class("MidaX86Sample"));
    assert!(!only_ime.saw_title("验证 x86 样本"));
}

#[test]
fn a_crash_is_not_excused_by_having_shown_a_window() {
    let crashed = LaunchObservation {
        windows: vec!["MidaX86Sample/验证 x86 样本".to_string()],
        saw_visible_window: true,
        first_window_ms: Some(15),
        exit_code: Some(0xC000_0005),
        exit_after_ms: 900,
        alive_at_deadline: false,
    };
    assert!(!crashed.exited_cleanly_or_alive());
}

#[test]
fn manifest_is_present_and_well_formed() {
    let case = load_manifest(&manifest_path());
    assert_eq!(case.case_id, "x86_sample");
    assert_eq!(case.sample_sha256.len(), 64);
    assert_eq!(case.reference_sha256.len(), 64);
    assert!(case.expect_resolved > 0);
    assert!(
        !case.expect_is_64bit,
        "this case is the 32-bit one; a PE32+ expectation here would mean the \
         manifest was copied from another case"
    );
    assert_eq!(
        case.expect_first_section_characteristics, 0x6000_0020,
        "the reference declares read-execute; a writable-text expectation would \
         encode the packer signature as the goal"
    );
    assert!(!case.expect_window_class.is_empty());
    assert!(!case.expect_window_title.is_empty());
    assert_eq!(
        case.expect_output_sha256.len(),
        64,
        "this case is byte-reproducible (measured 4/4); a placeholder here means \
         the nondeterminism came back"
    );
    // 302 written entries at 2 bytes each plus 11 page-block headers of 8 bytes
    // each is 604 + 88 = 692.  The two counts are different numbers on purpose
    // (requested vs. written), so assert the relation, not equality.
    assert_eq!(case.expect_relocation_entries, 296);
    assert_eq!(case.expect_relocation_blocks, 11);
    assert_eq!(
        case.expect_relocation_bytes,
        case.expect_relocation_table_entries * 2 + case.expect_relocation_blocks * 8,
        "the recorded byte size must equal entries x 2 plus block headers x 8"
    );
    assert!(
        case.expect_relocation_table_entries >= case.expect_relocation_entries,
        "the written table cannot hold fewer entries than the builder reported \
         generating"
    );
}
