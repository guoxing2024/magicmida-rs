//! End-to-end gate for the `Packed` VMProtect capture path.
//!
//! # What this gate is for
//!
//! A `Packed` target has `SizeOfRawData == 0` on every original section, so the
//! input file contains none of the code and no static path can recover it.
//! [`mida_cli`]'s `/dump-image --wait` reads the image out of a live process
//! without attaching a debugger and carves the payload that the packer
//! materialises only at run time.
//!
//! # Why it is `#[ignore]`d
//!
//! It has to launch a real process and read its memory, so it needs a desktop
//! session and it cannot run in CI.  The static half of the same capability
//! (identify, report, refuse to extract from the input file) is covered by
//! `vmprotect_static_gate`, which does run in CI.
//!
//! # The two goldens are different kinds of number
//!
//! * The **carved payload** is a hard golden.  Measured: 12,782,080 B hashing
//!   to `14596cbd…`, and that is byte-identical to the payload inside the
//!   reference image this project was given (`qidongqi\out\ida\main.exe`).
//! * The **whole image** is deliberately *not* hashed.  Three captures of the
//!   same sample at different moments produced three different values
//!   (`a68874e3…`, `28668aa3…`, `1963ed17…`) because a live image carries
//!   run-time state — resolved IAT pointers, the stack-guard cookie, timers.
//!   What is stable is the shape: 43,315,200 B and 9 sections, which is what
//!   the reference image has.
//!
//! # The elevation trap this gate has to survive
//!
//! This sample family registers a `RUNASADMIN` compatibility layer for its own
//! path (`HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\
//! Layers`) the first time it runs.  An elevated process cannot be opened with
//! `PROCESS_VM_READ` from an unelevated session — measured: `拒绝访问
//! (0x80070005)` — so the *second* run against the same path always fails.
//! The gate therefore copies the sample to a fresh path and clears the layer
//! key for that path first.  None of the three samples declares
//! `requestedExecutionLevel` in its manifest, so the flag is not what the
//! binary asks for; it is what this family installs.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Bytes of the reference image, which is the same shape a capture must have.
const EXPECT_IMAGE_SIZE: u64 = 43_315_200;

/// Sections in the reference image.
const EXPECT_SECTION_COUNT: usize = 9;

/// The payload inside the reference image.
const EXPECT_PAYLOAD_SHA256: &str =
    "14596cbdb54542a9bc33f955b92002b6f7029609f73753bfe9f384c6a2e5f21f";
const EXPECT_PAYLOAD_SIZE: u64 = 12_782_080;

fn sample() -> PathBuf {
    std::env::var_os("MIDA_VMPROTECT_PACKED_SAMPLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\Projects\zz_test.exe"))
}

fn cli() -> PathBuf {
    // Tests run with the crate directory as the working directory, so the
    // workspace root has to be derived rather than assumed.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/cli has two ancestors")
        .to_path_buf();
    let target = std::env::var("CARGO_BUILD_TARGET").unwrap_or_default();
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    let dir = if target.is_empty() {
        root.join("target").join(profile)
    } else {
        root.join("target").join(&target).join(profile)
    };
    // This gate is not built for i686: it launches an x64 `Packed` sample and a
    // 64-bit host is required to read its registers and memory layout.
    dir.join("mida-cli.exe")
}

fn sha256_file(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(&data);
    format!("{:x}", h.finalize())
}

/// Remove the `RUNASADMIN` compatibility layer for `path`, if present.
fn clear_runasadmin_layer(path: &Path) {
    let key = r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
    let value = path.to_string_lossy().into_owned();
    // `reg delete` exits 1 when the value is absent; that is not a failure.
    let _ = Command::new("reg")
        .args(["delete", key, "/v", &value, "/f"])
        .output();
}

#[test]
#[ignore = "needs the Packed VMProtect sample, a desktop session, and a fresh un-elevated path"]
fn packed_image_captures_and_carves_the_payload() {
    let sample = sample();
    if !sample.exists() {
        println!(
            "SKIP: no Packed VMProtect sample at {} — set MIDA_VMPROTECT_PACKED_SAMPLE",
            sample.display()
        );
        return;
    }

    let cli = cli();
    assert!(
        cli.exists(),
        "mida-cli not built at {} — run `cargo build` first",
        cli.display()
    );

    // A fresh path, because the family's own layer flag makes an already-run
    // path unreadable from an unelevated session.
    let work = std::env::temp_dir().join(format!("mida-vmp-packed-{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("create work dir");
    let copy = work.join("target.exe");
    std::fs::copy(&sample, &copy).expect("copy the sample");
    clear_runasadmin_layer(&copy);

    let child = Command::new(&copy)
        .current_dir(&work)
        .spawn()
        .unwrap_or_else(|e| panic!("cannot launch {}: {e}", copy.display()));
    let pid = child.id();

    let image_path = work.join("image.exe");
    let payload_path = work.join("image.rcdata131.bin");
    let _ = std::fs::remove_file(&image_path);
    let _ = std::fs::remove_file(&payload_path);

    let out = Command::new(&cli)
        .args([
            "/dump-image",
            &pid.to_string(),
            &image_path.to_string_lossy(),
            "--wait",
        ])
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", cli.display()));

    // The sample exits on its own a couple of seconds in, and the capture is
    // expected to survive that: a complete sample already read must not be
    // thrown away because the process went away before the next one.
    assert_eq!(
        out.status.code(),
        Some(0),
        "/dump-image failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let mut killer = child;
    let _ = killer.kill();

    // ---- the image has the reference's shape, not its bytes ----
    let size = std::fs::metadata(&image_path)
        .unwrap_or_else(|e| panic!("no image at {}: {e}", image_path.display()))
        .len();
    assert_eq!(
        size, EXPECT_IMAGE_SIZE,
        "captured image is {size} B, the reference image is {EXPECT_IMAGE_SIZE} B"
    );

    // ---- the payload is a hard golden ----
    let got = sha256_file(&payload_path);
    let got_size = std::fs::metadata(&payload_path)
        .unwrap_or_else(|e| panic!("no carved payload at {}: {e}", payload_path.display()))
        .len();
    assert_eq!(got_size, EXPECT_PAYLOAD_SIZE, "carved payload size drifted");
    assert_eq!(
        got, EXPECT_PAYLOAD_SHA256,
        "carved payload SHA-256 drifted from the reference image's payload"
    );
}

/// The input file must still be refused: nothing is extractable from it.
///
/// This is the half that keeps the branch honest — `/analyze --extract` on the
/// *input* has to say "not in the file", or the carve above would be pointless
/// and a user could believe a static extraction exists.
#[test]
#[ignore = "needs the Packed VMProtect sample"]
fn the_input_file_still_yields_nothing() {
    let sample = sample();
    if !sample.exists() {
        println!("SKIP: no Packed VMProtect sample at {}", sample.display());
        return;
    }
    let out = Command::new(cli())
        .args([
            "/analyze",
            &sample.to_string_lossy(),
            "--extract",
            &std::env::temp_dir().to_string_lossy(),
        ])
        .output()
        .expect("run /analyze");

    assert_eq!(
        out.status.code(),
        Some(1),
        "extracting from the input file must fail, not silently produce nothing"
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        all.contains("is not in the file"),
        "the refusal should say the resource is absent from the file; got:\n{all}"
    );
}

/// The decoded payload must be reproducible **offline**, from a captured image
/// alone — no live process, no retry, no luck.
///
/// This is the assertion that turns "the sample happens to write the file" into
/// "the pipeline produces it".  Measured transform: a single 32-byte repeating
/// XOR key, `K[i] == K[i-32]` holding across all 12,782,080 bytes with exactly
/// one distinct 32-byte block and only 31 distinct byte values.
///
/// The decoded product is then pinned to the **structural baseline**: the
/// measured payload is not an EXE but a `IMAGE_FILE_DLL` PE32+ with 9
/// sections, a self-consistent `SizeOfImage`, imports, and an ordinal-only
/// export directory (65,328 slots, zero names — the suite calls it by
/// ordinal), and it re-classifies as VMProtect `MinProtection` — original code
/// back in the file, which is the structural definition of "recovered".  The
/// behavioural half of the baseline lives in the `#[ignore]`d load test below.
///
/// It also checks the negative direction: the same key applied to a *different*
/// resource must not be accepted as a PE, which is what stops the transform
/// table from turning into blind decryption.
#[test]
fn the_decoded_payload_is_reproducible_from_a_captured_image_alone() {
    // Any captured image of this sample carries the container at the same RVA,
    // because the container lives in `.rsrc`.
    let reference = PathBuf::from(r"D:\Projects\qidongqi\out\ida\main.exe");
    if !reference.exists() {
        println!("SKIP: no reference image at {}", reference.display());
        return;
    }
    let image = std::fs::read(&reference).expect("read the reference image");
    let pe = mida_pe::PeHeader::from_bytes(&image).expect("parse the reference image");
    let resources = mida_packers_vmprotect::large_resources(&pe, &image);
    let container = resources
        .iter()
        .find(|r| r.name_id == Some(131))
        .expect("the reference image must carry RT_RCDATA id 131");

    let bytes = container
        .bytes(&image)
        .expect("the container must be fully present in a captured image");

    let transform = mida_packers_vmprotect::transform_for(container.type_id, container.name_id)
        .expect("a measured transform must exist for this resource");
    let decoded = transform.apply(bytes);

    assert!(
        mida_packers_vmprotect::looks_like_pe_image(&decoded),
        "the transform must yield a structurally valid PE image"
    );
    assert_eq!(
        sha256_hex(&decoded),
        "e7004e8901a640e9e1f254582df3ecbfc9300a7c2df3e46094922d86e8d64710",
        "the decoded payload drifted from the measured value"
    );

    // ---- the structural baseline of the decoded product -------------------
    //
    // "It looks like a PE" is not the claim; these are.  Measured 2026-10-26
    // on the decoded product of the reference image, and re-confirmed by the
    // behavioural load test: the product is a DLL the suite loads by
    // LoadLibrary, not a program CreateProcess would start.
    let dpe = mida_pe::PeHeader::from_bytes(&decoded)
        .expect("the decoded payload must parse as a full PE header");
    assert!(dpe.is_64bit, "the decoded payload should be PE32+");
    assert_eq!(dpe.sections.len(), 9, "the decoded payload should have 9 sections");
    assert!(
        mida_packers_vmprotect::is_dll_image(&decoded),
        "the decoded payload must carry IMAGE_FILE_DLL — naming it .exe \
         makes the OS refuse it with 'not a valid application'"
    );

    // SizeOfImage must agree with what the section table describes, or the
    // Windows loader maps the image wrong before any of our code runs.
    let span = dpe
        .sections
        .iter()
        .map(|s| s.virtual_address.saturating_add(s.virtual_size))
        .max()
        .expect("sections");
    let aligned = span.div_ceil(dpe.section_alignment) * dpe.section_alignment;
    assert_eq!(
        aligned,
        dpe.nt_headers.optional_header.size_of_image,
        "SizeOfImage does not match the section table — the loader would \
         refuse or mis-map this image"
    );

    // Import directory must be present and resolvable-shape; the export
    // directory must be the measured ordinal-only form.
    const IMPORT_DIR: usize = 1;
    const EXPORT_DIR: usize = 0;
    let imp = dpe.nt_headers.optional_header.data_directory[IMPORT_DIR];
    assert_ne!(imp.virtual_address, 0, "no import directory — nothing could load this");
    let exp = dpe.nt_headers.optional_header.data_directory[EXPORT_DIR];
    assert_ne!(exp.virtual_address, 0, "no export directory — the suite could not call it");
    let exp_bytes = read_rva(&dpe, &decoded, exp.virtual_address as usize, exp.size as usize)
        .expect("export directory bytes must be inside the decoded image");
    // NumberOfFunctions at +20, NumberOfNames at +24 (IMAGE_EXPORT_DIRECTORY).
    let n_funcs = u32::from_le_bytes(exp_bytes[20..24].try_into().unwrap());
    let n_names = u32::from_le_bytes(exp_bytes[24..28].try_into().unwrap());
    assert_eq!(n_funcs, 65_328, "export slot count moved");
    assert_eq!(n_names, 0, "measured ordinal-only exports; names appearing is a change");
    assert!(
        exp.size as usize >= 24 + n_funcs as usize * 4,
        "export directory too small for its own function table"
    );

    // And the decisive classification: the product of the Packed line is a
    // MinProtection target — original code back in the file, entry point
    // present, nothing requiring a runtime dump.  That is the structural
    // definition of "the original program was recovered".
    let report = mida_packers_vmprotect::analyze(&dpe, &decoded);
    assert_eq!(
        report.mode,
        mida_packer_api::VmProtectMode::MinProtection,
        "the decoded payload must re-classify as MinProtection"
    );
    assert!(
        !report.requires_runtime_dump(),
        "a recovered program must not itself demand a runtime dump"
    );

    // A wrong key must be rejected by the data, not by trusting the table.
    let mut wrong = transform.xor_key.to_vec();
    wrong[0] ^= 0xff;
    let garbage: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ wrong[i % wrong.len()])
        .collect();
    assert!(
        !mida_packers_vmprotect::looks_like_pe_image(&garbage),
        "a corrupted key must not be accepted as producing a PE image"
    );
}

/// Map an RVA inside `image` to a byte slice, using the section table of `pe`.
fn read_rva<'a>(
    pe: &mida_pe::PeHeader,
    image: &'a [u8],
    rva: usize,
    size: usize,
) -> Option<&'a [u8]> {
    let s = pe.sections.iter().find(|s| {
        let va = s.virtual_address as usize;
        va <= rva && rva + size <= va + s.virtual_size.max(s.raw_size) as usize
    })?;
    let off = s.raw_offset as usize + (rva - s.virtual_address as usize);
    image.get(off..off + size)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Cheap guard on the constants above: the section count is part of the shape
/// assertion, and it must match what the reference image actually has.
#[test]
fn the_expected_section_count_matches_the_reference() {
    let reference = PathBuf::from(r"D:\Projects\qidongqi\out\ida\main.exe");
    if !reference.exists() {
        println!("SKIP: no reference image at {}", reference.display());
        return;
    }
    let pe = mida_pe::PeHeader::from_file(&reference).expect("parse the reference image");
    assert_eq!(
        pe.sections.len(),
        EXPECT_SECTION_COUNT,
        "the reference image no longer has {EXPECT_SECTION_COUNT} sections"
    );
    assert_eq!(
        std::fs::metadata(&reference).unwrap().len(),
        EXPECT_IMAGE_SIZE,
        "the reference image size changed"
    );
}

/// The payload **decoded to a real PE** is produced by the application, not by
/// the packer — and it is written to `%TEMP%\<guid>.log`.
///
/// # What was measured
///
/// The resource region freezes at `14596cbd…` (encrypted) and never changes
/// again before the process exits; watching every region in the address space
/// whose size is near 12,782,080 B for 22 s found no `MZ` anywhere, and no child
/// process is created.  So VMProtect's own output stops at `14596cbd…`.
///
/// The decoded PE (`e7004e89…`, `MZ`, `e_lfanew 0x80`, `machine 0x8664`,
/// 9 sections) appears instead as a `%TEMP%\<guid>.log` file, written while the
/// sample runs.  Measured across four controlled runs: **two wrote it and two
/// did not**, the writes landing at t≈3.55 s with the process exiting earlier
/// (4.4 s) than in the runs that did not write (6.5–6.8 s).  So it is a
/// branch-dependent side effect, and a single run is not enough — hence the
/// retry loop below.
///
/// This test is therefore allowed to skip when no run produces the file: it
/// asserts the *relationship* (if the file appears, it is exactly that PE), not
/// that it must appear on any given run.
#[test]
#[ignore = "needs the Packed VMProtect sample, a desktop session, and several launches"]
fn the_decoded_payload_is_a_pe_that_the_sample_writes_to_temp() {
    let sample = sample();
    if !sample.exists() {
        println!("SKIP: no Packed VMProtect sample at {}", sample.display());
        return;
    }
    let temp = std::env::temp_dir();
    let size_of_interest = EXPECT_PAYLOAD_SIZE;

    // Files that already exist are other runs' leftovers.
    let before: std::collections::HashSet<String> = std::fs::read_dir(&temp)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.metadata()
                .map(|m| m.is_file() && m.len() == size_of_interest)
                .unwrap_or(false)
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    let mut found: Option<PathBuf> = None;
    for attempt in 1..=6 {
        let work = temp.join(format!(
            "mida-vmp-decode-{}-{attempt}",
            std::process::id()
        ));
        std::fs::create_dir_all(&work).expect("create work dir");
        let copy = work.join("target.exe");
        std::fs::copy(&sample, &copy).expect("copy the sample");
        clear_runasadmin_layer(&copy);

        let mut child = Command::new(&copy)
            .current_dir(&work)
            .spawn()
            .unwrap_or_else(|e| panic!("cannot launch {}: {e}", copy.display()));

        // Poll for up to 12 s; the write lands at about 3.5 s when it happens.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
        while std::time::Instant::now() < deadline {
            if let Ok(dir) = std::fs::read_dir(&temp) {
                for e in dir.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if before.contains(&name) {
                        continue;
                    }
                    if e.metadata().map(|m| m.len()).ok() == Some(size_of_interest) {
                        found = Some(e.path());
                        break;
                    }
                }
            }
            if found.is_some() || child.try_wait().map(|s| s.is_some()).unwrap_or(false) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
        let _ = child.kill();
        if found.is_some() {
            println!("the decoded PE appeared on attempt {attempt}");
            break;
        }
        println!("attempt {attempt}: no decoded payload written");
    }

    let Some(path) = found else {
        println!(
            "SKIP: no run wrote the decoded payload; measured to happen on roughly half of \
             launches, so this is not a failure"
        );
        return;
    };

    assert_eq!(
        sha256_file(&path),
        "e7004e8901a640e9e1f254582df3ecbfc9300a7c2df3e46094922d86e8d64710",
        "the written payload is not the measured decoded PE"
    );

    let pe = mida_pe::PeHeader::from_file(&path).expect("the decoded payload must parse as a PE");
    assert!(pe.is_64bit, "the decoded payload should be PE32+");
    assert_eq!(
        pe.sections.len(),
        9,
        "the decoded payload should have 9 sections"
    );

    let _ = std::fs::remove_file(&path);
}
// ---------------------------------------------------------------------------
// The behavioural half of the reconciliation baseline
// ---------------------------------------------------------------------------

/// Build the load probe (`tests/fixtures/vmp_load_probe.c`) with the same
/// bare-`gcc` convention the Themida DLL gate uses for its harness.
fn build_load_probe(out_dir: &Path) -> PathBuf {
    let exe = out_dir.join("vmp_load_probe.exe");
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("vmp_load_probe.c");
    assert!(src.exists(), "probe source missing at {}", src.display());
    let output = Command::new("gcc")
        .arg("-O2")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .output()
        .unwrap_or_else(|e| panic!("cannot run gcc to build the load probe: {e}"));
    assert!(
        output.status.success(),
        "probe build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    exe
}

/// The decoded product must **load and initialise** the way the launcher
/// family actually uses it.
///
/// # Why this exists, and why it says LoadLibrary
///
/// The product carries `IMAGE_FILE_DLL`; the family writes these exact bytes
/// to `%TEMP%\<guid>.log` at run time (byte-reconciled by the test above) and
/// loads them with `LoadLibrary`, not `CreateProcess`.  Measured 2026-10-26 on
/// the reference decode:
///
///   LOADED=1, EXPORT_SLOTS=65328 NAMES=0 NONZERO=60 BASE=37,
///   FIRST_EXPORT ordinal=66 resolves=1, THREADS=4, exit 0
///
/// So the behavioural baseline is not "a window appears" (there is none) and
/// not "the process starts" (the OS refuses a DLL image: "is not a valid
/// application for this OS platform").  It is: a host can map it, its
/// `DllMain` completes and starts its worker threads, and the ordinal-only
/// exports resolve.  A decode that is byte-wrong would fail somewhere in that
/// chain — the imports are resolved, the relocations applied, the TLS
/// initialisers run, `DllMain` executes — which is what makes this a real
/// behavioural check rather than a structural one.
///
/// The probe runs in a **sacrificial child process** (the DLL is third-party
/// and spawns threads; loading it into the test runner would leave the test
/// process polluted and make a hang unrecoverable).  It is also why this test
/// is `#[ignore]`d: it executes third-party code, which CI must not do.
///
/// # Measured discriminating power (2026-10-26)
///
/// One flipped byte inside `.text` — code `DllMain` never executes — still
/// loads cleanly: this probe does **not** see dead-code corruption.  That is
/// the byte golden's job (the SHA-256 assert above is exact).  One flipped
/// byte inside `.rdata2` (the VM runtime section, executed during
/// initialisation) crashes the host with an access violation, and the probe's
/// non-zero exit turns this gate red.  So the split of duty is: the golden
/// answers "are these the right bytes", this gate answers "does the product
/// actually survive the loader and initialise".
#[test]
#[ignore = "LoadLibrary's a third-party payload DLL in a sacrificial process: needs a desktop session and gcc"]
fn the_decoded_dll_loads_and_initializes() {
    let reference = PathBuf::from(r"D:\Projects\qidongqi\out\ida\main.exe");
    if !reference.exists() {
        println!("SKIP: no reference image at {}", reference.display());
        return;
    }

    // ---- decode exactly as the pipeline does ----
    let image = std::fs::read(&reference).expect("read the reference image");
    let pe = mida_pe::PeHeader::from_bytes(&image).expect("parse the reference image");
    let container = mida_packers_vmprotect::large_resources(&pe, &image)
        .into_iter()
        .find(|r| r.name_id == Some(131))
        .expect("the reference image must carry RT_RCDATA id 131");
    let bytes = container.bytes(&image).expect("container must be in the image");
    let transform = mida_packers_vmprotect::transform_for(container.type_id, container.name_id)
        .expect("a measured transform must exist");
    let decoded = transform.apply(bytes);
    assert!(
        mida_packers_vmprotect::is_dll_image(&decoded),
        "the probe expects the measured DLL payload"
    );

    let work = std::env::temp_dir().join(format!("mida-vmp-load-{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("create work dir");
    let product = work.join("product.dll");
    std::fs::write(&product, &decoded).expect("write the decoded product");
    let probe = build_load_probe(&work);

    // ---- run the probe with a hard timeout ----
    //
    // If the product's DllMain deadlocks, LoadLibraryW never returns; the test
    // must fail with the probe's partial output instead of hanging forever.
    let mut child = Command::new(&probe)
        .arg(&product)
        .arg("6")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start the load probe: {e}"));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().expect("wait on probe") {
            break s;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let out = child.wait_with_output().expect("collect after kill");
            panic!(
                "the load probe did not finish in 30 s — the product's DllMain \
                 likely deadlocked. Partial output:\n{}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let out = child.wait_with_output().expect("collect probe output");
    let log = String::from_utf8_lossy(&out.stdout).to_string()
        + &String::from_utf8_lossy(&out.stderr);

    assert!(
        status.success(),
        "the product did not load/initialise cleanly (probe exit {:?}):\n{log}",
        status.code()
    );

    // ---- the baseline assertions ----
    let field = |line_prefix: &str, key: &str| -> Option<String> {
        log.lines()
            .find(|l| l.starts_with(line_prefix))
            .and_then(|l| {
                l.split_whitespace()
                    .find_map(|t| t.strip_prefix(&format!("{key}=")).map(str::to_string))
            })
    };

    assert_eq!(
        field("LOADED=", "LOADED").as_deref(),
        Some("1"),
        "LoadLibrary failed:\n{log}"
    );

    // Exports: the measured ordinal-only table, identical in the file and in
    // the loaded image.
    assert_eq!(
        field("EXPORT_SLOTS=", "EXPORT_SLOTS").as_deref(),
        Some("65328"),
        "export slot count moved:\n{log}"
    );
    assert_eq!(
        field("EXPORT_SLOTS=", "NAMES").as_deref(),
        Some("0"),
        "the suite calls this DLL by ordinal; named exports appearing is a change:\n{log}"
    );
    assert_eq!(
        field("EXPORT_SLOTS=", "NONZERO").as_deref(),
        Some("60"),
        "non-empty export entries moved:\n{log}"
    );
    assert_eq!(
        field("FIRST_EXPORT", "ordinal").as_deref(),
        Some("66"),
        "first exported ordinal moved:\n{log}"
    );
    assert_eq!(
        field("FIRST_EXPORT", "resolves").as_deref(),
        Some("1"),
        "GetProcAddress by ordinal must resolve the first export:\n{log}"
    );

    // DllMain completed and started the measured worker threads (4 observed;
    // >= 2 tolerates one thread exiting early without losing the signal).
    let threads: u32 = field("THREADS=", "THREADS")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("probe reported no thread count:\n{log}"));
    assert!(
        threads >= 2,
        "DllMain started no worker threads (observed {threads}) — the payload \
         did not initialise:\n{log}"
    );

    let _ = std::fs::remove_dir_all(&work);
}
