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
use std::process::Command;

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