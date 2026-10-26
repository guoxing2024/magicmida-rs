//! Behaviour gate for the UPX static unpacker's products.
//!
//! The byte gate (`upx_static_gate.rs`) proves the products are
//! byte-for-byte `upx -d`'s output.  Byte equality with a *reference file*
//! says nothing, by itself, about whether the rebuilt PE actually **runs** —
//! that gap is exactly what burned the project once on the Themida side (a
//! product that loaded, resolved its imports, and still answered "0.0"
//! because a section was written too late).  This gate closes it for UPX the
//! same way the Themida EXE gate does it: with a **control sample**.
//!
//! ## The control method
//!
//! The corpus originals are `mida-cli` v0.3.0 binaries (x64 and x86 — the
//! same sizes as the released artifacts).  Each product and its pre-pack
//! original are both run with `/version`, and the gate asserts:
//!
//! 1. the product **exits 0** — a rebuild that broke imports, relocations or
//!    the TLS directory dies before `main` with a loader status
//!    (e.g. `0xC0000135`), which lands here as a non-zero exit;
//! 2. the product's stdout **equals the original's** — same version string,
//!    so the product is not merely alive but is the same program;
//! 3. the original's stdout starts with `mida-cli ` — guards against both
//!    sides failing identically into an empty-cmpares-empty pass.
//!
//! Behaviour (stdout + exit code) is compared, not bytes: the product is
//! `upx -d`'s output, which deliberately differs from the pre-pack original
//! in the DOS-stub area — a difference this gate must not care about.
//!
//! `/version` is the ideal probe: it is a direct print-and-exit command, so
//! the gate needs **no desktop session and no stdin** and runs by default,
//! like the byte gate.  `injector_x64.upx.exe` is deliberately excluded: its
//! original is ScyllaHide's process injector, and spawning an injector from
//! a test is a side-effect risk that the mida-cli products (which already
//! exercise the full rebuild of a 6 MB image) do not need.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use mida_packers_upx::unpack_static;
use mida_pe::PeHeader;

/// `(packed sample, pre-pack original used as the behaviour control)`.
const CORPUS: &[(&str, &str)] = &[
    ("mida_x64_nrv.upx.exe", "mida_x64_nrv.exe"),
    ("mida_x64_lzma.upx.exe", "mida_x64_nrv.exe"),
    ("mida_x64_nrv2b.upx.exe", "mida_x64_nrv.exe"),
    ("mida_x64_nrv2d.upx.exe", "mida_x64_nrv.exe"),
    ("mida_x86_nrv.upx.exe", "mida_x86_nrv.exe"),
    ("mida_x86_b.upx.exe", "mida_x86_nrv.exe"),
];

fn sample_dir() -> PathBuf {
    std::env::var_os("MIDA_UPX_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\Projects\Magicmida-RS\OUT\upx_samples"))
}

/// What a probe run observed: exit code and stdout.
struct Run {
    code: i32,
    stdout: String,
}

/// Run `exe /version` and capture the result.
///
/// `CREATE_NO_WINDOW` so a test run never flashes a console; stdin is null
/// so the child can never block on input.
fn probe(exe: &Path) -> Run {
    use std::os::windows::process::CommandExt;
    let out = Command::new(exe)
        .arg("/version")
        .stdin(Stdio::null())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .unwrap_or_else(|e| panic!("{} must spawn: {e}", exe.display()));
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// Unpack `packed` and write the product next to nothing — a unique temp
/// path — returning the path.  The caller removes it.
fn unpack_to_temp(packed_bytes: &[u8], tag: &str) -> PathBuf {
    let pe = PeHeader::from_bytes(packed_bytes).expect("packed sample parses as PE");
    let product = unpack_static(&pe, packed_bytes).expect("static unpack");
    let path = std::env::temp_dir().join(format!(
        "mida_upx_behavior_{}_{}.exe",
        std::process::id(),
        tag
    ));
    std::fs::write(&path, &product).expect("write product to temp");
    path
}

#[test]
fn unpacked_products_run_and_match_their_control_sample() {
    let dir = sample_dir();
    if !dir.exists() {
        println!("SKIP: no UPX sample dir at {}", dir.display());
        return;
    }

    for (packed, control) in CORPUS {
        let packed_path = dir.join(packed);
        let Ok(packed_bytes) = std::fs::read(&packed_path) else {
            println!(
                "SKIP: {} not readable; this part of the gate tested nothing",
                packed_path.display()
            );
            continue;
        };
        let control_path = dir.join(control);
        // The control runs from its corpus path; its bytes are never needed.

        // The control must behave like a mida-cli before it can be a
        // control: otherwise both sides could fail identically into a pass.
        let control_run = probe(&control_path);
        assert_eq!(
            control_run.code, 0,
            "{} must exit 0 on /version to qualify as the control",
            control_path.display()
        );
        assert!(
            control_run.stdout.starts_with("mida-cli "),
            "{} must answer the version banner, got {:?}",
            control_path.display(),
            control_run.stdout
        );

        let product_path = unpack_to_temp(&packed_bytes, packed);
        let product_run = probe(&product_path);
        let _ = std::fs::remove_file(&product_path);

        assert_eq!(
            product_run.code, 0,
            "{packed}: the product must run and exit 0 (a non-zero loader \
             status here means the rebuild broke the image)"
        );
        assert_eq!(
            product_run.code, control_run.code,
            "{packed}: exit code must match the control"
        );
        assert_eq!(
            product_run.stdout, control_run.stdout,
            "{packed}: /version output must match the control"
        );
        println!(
            "OK: {packed} -> {} B product answers {:?} like its control",
            packed_bytes.len(),
            product_run.stdout.trim()
        );
    }
}
