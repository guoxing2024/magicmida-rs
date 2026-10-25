//! Static gate for the UPX branch.
//!
//! Same philosophy as the VMProtect static gate: pure file work, runs by
//! default, and **skips with an explicit `SKIP:` message** when the samples
//! are absent (they live outside the repository and are trivially
//! regenerable with `upx` — see `OUT\upx_layout.py` for how they were made).
//!
//! Override the sample directory with `MIDA_UPX_CORPUS`
//! (default `D:\Projects\Magicmida-RS\OUT\upx_samples`).
//!
//! Every golden value below was measured on UPX 5.2.1 output on 2026-10-26
//! (`OUT\upx_layout.py` / `OUT\upx_layout2.py` / `OUT\upx_adler.py`) and
//! cross-checked against `src/packhead.cpp` + `src/pefile.cpp` at tag v5.2.1.

use std::path::PathBuf;

use mida_packers_upx::{analyze, detect, find_pack_header};
use mida_pe::PeHeader;

struct Sample {
    name: &'static str,
    file_len: u64,
    format: u8,
    method: u8,
    u_len: u32,
    c_len: u32,
    u_file_size: u32,
    filter: u8,
    filter_cto: u8,
    overlay: u64,
}

/// Measured goldens, one per packed sample.
const SAMPLES: &[Sample] = &[
    Sample {
        name: "injector_x64.upx.exe",
        file_len: 364_032,
        format: 36,
        method: 8,
        u_len: 825_011,
        c_len: 286_627,
        u_file_size: 794_624,
        filter: 73,
        filter_cto: 23,
        overlay: 0,
    },
    Sample {
        name: "mida_x64_nrv.upx.exe",
        file_len: 3_469_061,
        format: 36,
        method: 8,
        u_len: 4_344_114,
        c_len: 1_374_037,
        u_file_size: 6_379_269,
        filter: 73,
        filter_cto: 55,
        overlay: 2_091_269,
    },
    Sample {
        name: "mida_x64_lzma.upx.exe",
        file_len: 3_246_853,
        format: 36,
        method: 14,
        u_len: 4_344_114,
        c_len: 1_149_633,
        u_file_size: 6_379_269,
        filter: 73,
        filter_cto: 55,
        overlay: 2_091_269,
    },
    Sample {
        name: "mida_x86_nrv.upx.exe",
        file_len: 3_578_421,
        format: 9,
        method: 8,
        u_len: 4_218_970,
        c_len: 1_479_179,
        u_file_size: 6_234_165,
        filter: 38,
        filter_cto: 38,
        overlay: 2_096_693,
    },
];

fn sample_dir() -> PathBuf {
    std::env::var_os("MIDA_UPX_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\Projects\Magicmida-RS\OUT\upx_samples"))
}

fn read_sample(dir: &PathBuf, name: &str) -> Option<(PathBuf, Vec<u8>)> {
    let path = dir.join(name);
    match std::fs::read(&path) {
        Ok(bytes) => Some((path, bytes)),
        Err(e) => {
            println!(
                "SKIP: {} not readable ({e}); this part of the gate tested nothing",
                path.display()
            );
            None
        }
    }
}

/// Every golden field of every measured sample.
#[test]
fn every_measured_sample_matches_its_golden_header() {
    let dir = sample_dir();
    if !dir.exists() {
        println!("SKIP: no UPX sample dir at {} — set MIDA_UPX_CORPUS", dir.display());
        return;
    }
    let mut checked = 0usize;
    for s in SAMPLES {
        let Some((path, bytes)) = read_sample(&dir, s.name) else {
            continue;
        };
        checked += 1;
        assert_eq!(bytes.len() as u64, s.file_len, "{} changed size", path.display());
        let pe = PeHeader::from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("{} must parse as a PE: {e}", path.display()));
        let d = detect(&pe, &bytes)
            .unwrap_or_else(|| panic!("{} must classify as UPX", path.display()));
        assert_eq!(d.kind, mida_packer_api::PackerKind::Upx, "{}", path.display());
        let codes: Vec<&str> = d.evidence.iter().map(|e| e.code).collect();
        assert!(codes.contains(&"upx-packheader"), "{codes:?}");
        assert!(codes.contains(&"upx-sections"), "{codes:?}");

        let ph = find_pack_header(&bytes)
            .unwrap_or_else(|| panic!("{} must carry a PackHeader", path.display()));
        assert_eq!(ph.format, s.format, "{} format", path.display());
        assert_eq!(ph.method, s.method, "{} method", path.display());
        assert_eq!(ph.u_len, s.u_len, "{} u_len", path.display());
        assert_eq!(ph.c_len, s.c_len, "{} c_len", path.display());
        assert_eq!(ph.u_file_size, s.u_file_size, "{} u_file_size", path.display());
        assert_eq!(ph.filter, s.filter, "{} filter", path.display());
        assert_eq!(ph.filter_cto, s.filter_cto, "{} filter_cto", path.display());
        assert!(ph.checksum_ok(&bytes), "{} header checksum", path.display());
    }
    assert_eq!(checked, SAMPLES.len(), "all measured samples must be present");
}

/// The two structural invariants, on every sample: the computed unpacker-stub
/// offset equals the entry point's file offset, and `c_adler` verifies over
/// the in-file stream.
#[test]
fn layout_invariant_and_stream_checksum_hold_on_every_sample() {
    let dir = sample_dir();
    if !dir.exists() {
        println!("SKIP: no UPX sample dir at {}", dir.display());
        return;
    }
    for s in SAMPLES {
        let Some((path, bytes)) = read_sample(&dir, s.name) else {
            continue;
        };
        let pe = PeHeader::from_bytes(&bytes).expect("PE header");
        let r = analyze(&pe, &bytes)
            .unwrap_or_else(|| panic!("{} must produce a report", path.display()));
        assert!(
            r.entry_point_matches_stub,
            "{}: computed stub {:#x} vs entry point {:?}",
            path.display(),
            r.stub_file_offset,
            r.entry_point_file_offset
        );
        assert!(r.c_adler_ok, "{}: c_adler over the stream must verify", path.display());
        assert_eq!(r.overlay_size, s.overlay, "{} overlay", path.display());
    }
}

/// Negative controls: an unpacked PE and a Themida sample are never claimed.
#[test]
fn unpacked_and_themida_files_are_never_claimed() {
    let negative = |env: &str, default: &str, marker: &str| {
        let path = PathBuf::from(std::env::var(env).unwrap_or_else(|_| default.to_string()));
        let Ok(bytes) = std::fs::read(&path) else {
            println!("SKIP: {env} -> {} not readable", path.display());
            return;
        };
        let pe = PeHeader::from_bytes(&bytes).expect("PE header");
        assert!(
            detect(&pe, &bytes).is_none(),
            "{path:?} was claimed as UPX — a false positive"
        );
        let _ = marker;
    };
    negative(
        "MIDA_UPX_NEGATIVE_CLEAN",
        r"D:\Projects\Magicmida-RS\src\target\release\mida-cli.exe",
        "clean",
    );
    negative(
        "MIDA_UPX_NEGATIVE_THEMIDA",
        r"D:\Projects\shiguang\时光一键宏.exe",
        "themida",
    );
}

/// Why the `/unpack` packer gate needs UPX *before* the Themida heuristic:
/// `UPX0` is an executable section with `raw_size == 0` and a large virtual
/// size — exactly the shape `is_themida_section` keys on.  Measured here, on
/// the real sections, so the claim carries evidence instead of being an
/// assertion about intent.
#[test]
fn the_upx0_section_would_fire_themidas_heuristic() {
    let dir = sample_dir();
    if !dir.exists() {
        println!("SKIP: no UPX sample dir at {}", dir.display());
        return;
    }
    let Some((path, bytes)) = read_sample(&dir, "injector_x64.upx.exe") else {
        return;
    };
    let pe = PeHeader::from_bytes(&bytes).expect("PE header");
    let upx0 = pe
        .sections
        .iter()
        .find(|s| s.name == "UPX0")
        .expect("UPX0 section");
    assert!(
        mida_packers_themida::is_themida_section(upx0),
        "UPX0 must fire is_themida_section — if this flips, the /unpack gate \
         order stopped being load-bearing and this test documents a change"
    );
    let _ = path;
}
