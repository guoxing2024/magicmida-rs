//! Corpus gate for the Themida/WinLicense **version ladder**.
//!
//! ## What corpus, and where it came from
//!
//! The ladder is the Tuts 4 You "Collection 2011" `UnPackMe Collection/PE32`
//! members, fetched per-member over HTTP range requests from
//! <https://archive.org/details/tuts-4-you-collection-2011_202405> on
//! 2026-10-26 (see `RUNBOOK.md` for the reproducible fetch recipe).  Each
//! unpack-me is labelled by the exact packer version that produced it, which
//! is what makes it a *version ladder* rather than just a sample pile:
//!
//! ```text
//! Themida 1.1.1.0 … 1.9.1.0 · WinLicense 1.1.1.0 … 1.8.9.0  →  1.x generation
//! WinLicense 2.0.1.0 · 2.0.6.5 (CISC/RISC examples)          →  SecureEngine 2.x
//! WinLicense 2.0.8.0                                          →  classic surface
//! ```
//!
//! The corpus lives outside the repository (~90 MB of third-party challenge
//! binaries), so this gate **skips with an explicit message** when it is
//! absent — same contract as the VMProtect corpus gate.  Override with
//!
//! ```text
//! MIDA_THEMIDA_LADDER=<dir>   (default D:\Projects\Magicmida-RS\OUT\v1v2\unpackmes\x)
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use mida_packers_themida::{
    detect_version_with_image, is_themida_section, ThemidaVersion,
};
use mida_pe::PeHeader;

fn ladder_dir() -> PathBuf {
    std::env::var_os("MIDA_THEMIDA_LADDER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\Projects\Magicmida-RS\OUT\v1v2\unpackmes\x"))
}

/// The expected generation for one sample, from the measured facts recorded in
/// `version/mod.rs`'s type documentation.
fn expected_version(dir_name: &str, pe: &PeHeader) -> Option<ThemidaVersion> {
    // The `"Themida "` section name (trailing space) is the ladder-measured
    // marker of 1.1.1–1.8.2 builds.
    let named_ancient = pe
        .sections
        .iter()
        .any(|s| &s.header.name == b"Themida ");

    let dir = dir_name.to_ascii_lowercase();
    if dir.contains("2.0.1.0") || dir.contains("2.0.6.5") {
        return Some(ThemidaVersion::V2);
    }
    if dir.contains("2.0.8.0") {
        // Measured: WinLicense 2.0.8 carries the classic two-DLL import
        // surface, so the static classifier answers V1.  The ambiguity is
        // documented, not hidden.
        return Some(ThemidaVersion::V1);
    }
    if dir.contains("themida 1.") || dir.contains("winlicense 1.") {
        // Files sitting directly in the root are the 1.8.2.0 unpack-me (its
        // rar had no subdirectory).
        if named_ancient {
            Some(ThemidaVersion::Ancient)
        } else {
            Some(ThemidaVersion::V1)
        }
    } else if named_ancient {
        Some(ThemidaVersion::Ancient)
    } else {
        None
    }
}

#[test]
fn the_version_ladder_classifies_by_measured_generation() {
    let dir = ladder_dir();
    if !dir.exists() {
        println!(
            "SKIP: no Themida version ladder at {} — set MIDA_THEMIDA_LADDER; \
             this gate tested nothing",
            dir.display()
        );
        return;
    }

    let mut checked = 0usize;
    let mut with_themida_section = 0usize;
    let mut wrong: Vec<String> = Vec::new();
    let mut by_dir: BTreeMap<String, (usize, usize)> = BTreeMap::new();

    // Recursive walk: the 2.0.6.5 rar nests its CISC/RISC examples one level
    // deeper (dir/(CISC-1) Examples-LCF-AT/CISC-1.exe).  The version dir is
    // whatever directory sits directly under the corpus root; files extracted
    // straight into the root belong to the 1.8.2.0 unpack-me (its rar had no
    // subdirectory).
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).expect("read ladder directory") {
            let path = entry.expect("ladder entry").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
            {
                let version_dir = path
                    .parent()
                    .and_then(|p| p.strip_prefix(root).ok())
                    .and_then(|rel| rel.components().next())
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .unwrap_or_else(|| "Themida 1.8.2.0 (root)".to_string());
                out.push((path, version_dir));
            }
        }
    }

    let mut samples: Vec<(PathBuf, String)> = Vec::new();
    walk(&dir, &dir, &mut samples);

    for (file, dir_name) in samples {
        let Ok(image) = std::fs::read(&file) else {
            continue;
        };
        let Ok(pe) = PeHeader::from_bytes(&image) else {
            // Non-PE stragglers are skipped loudly, not silently.
            println!("note: {} does not parse as PE — skipped", file.display());
            continue;
        };
        checked += 1;

        if pe.sections.iter().any(is_themida_section) {
            with_themida_section += 1;
        }

        let Some(expected) = expected_version(&dir_name, &pe) else {
            wrong.push(format!(
                "{}: no expectation derived from directory {dir_name:?}",
                file.display()
            ));
            continue;
        };
        let got = detect_version_with_image(&pe, pe.is_64bit, &image);
        let e = by_dir.entry(dir_name.clone()).or_insert((0, 0));
        e.1 += 1;
        if got == expected {
            e.0 += 1;
        } else {
            wrong.push(format!(
                "{}: expected {expected:?}, got {got:?}",
                file.display()
            ));
        }
    }

    for (d, (ok, total)) in &by_dir {
        println!("  {d}: {ok}/{total} classified as expected");
    }
    println!(
        "ladder: {checked} PEs checked, {with_themida_section} carry a Themida-section shape"
    );

    assert!(
        checked >= 60,
        "expected the ladder corpus (>= 60 unpack-mes), saw {checked}"
    );
    assert!(
        with_themida_section == checked,
        "every ladder sample must carry a Themida-section shape — that is the \
         routing precondition for the whole pipeline"
    );
    assert!(
        wrong.is_empty(),
        "these ladder samples misclassified:\n{}",
        wrong.join("\n")
    );
}
