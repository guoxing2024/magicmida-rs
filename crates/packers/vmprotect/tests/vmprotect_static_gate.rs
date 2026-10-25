//! Static gate for the VMProtect branch.
//!
//! ## Why this test is *not* `#[ignore]`
//!
//! The three existing e2e gates (`e2e_gate`, `dll_e2e_gate`, `x86_e2e_gate`)
//! are all `#[ignore]`d because `/unpack` injects ScyllaHide and the target
//! puts a window on screen — they need an interactive desktop session.  This
//! gate only reads files, so it runs by default: the VMProtect branch is the
//! first capability in this project that CI can actually verify.
//!
//! ## Skip, do not fail
//!
//! The samples live outside the repository (19 MB and 21 MB of a third
//! party's product), so the gate **skips with an explicit message** when they
//! are absent rather than failing.  A skip is printed with `SKIP:` so a
//! green-but-empty run is distinguishable from a green run that tested
//! something.
//!
//! Override the paths with:
//!
//! ```text
//! MIDA_VMPROTECT_MIN_SAMPLE=<path>   (default D:\Projects\lunlun\伦伦软件.exe)
//! MIDA_VMPROTECT_PACKED_SAMPLE=<path> (default D:\Projects\zz_test.exe)
//! MIDA_VMPROTECT_THEMIDA_SAMPLE=<path> (default D:\Projects\shiguang\时光一键宏.exe)
//! ```

use std::path::{Path, PathBuf};

use mida_packer_api::VmProtectMode;
use mida_packers_vmprotect::{analyze, detect, section_name, RT_RCDATA};
use mida_pe::PeHeader;

/// Golden values for `D:\Projects\lunlun\伦伦软件.exe` (`MinProtection`).
mod min_protection {
    pub const SIZE: usize = 19_005_952;
    pub const PAYLOAD_SIZE: u32 = 16_102_969;
    pub const PAYLOAD_SHA256: &str =
        "91d585e646033b68013958061cdd747be1170329eacd18951d6c3eb0f78f9123";
    pub const PAYLOAD_MAGIC: &str = "XMP2QH_";
    pub const PAYLOAD_ID: u32 = 101;
    pub const TRAMPOLINES: usize = 14;
    pub const PDATA_TRIPLES: (usize, usize) = (0, 64);
    pub const EXCEPTION_SECTION: &str = ".vmp0";
    pub const EXCEPTION_TRIPLES: (usize, usize) = (64, 64);
    pub const RUNTIME_SECTION: &str = ".vmp0";
}

/// Golden values for `D:\Projects\zz_test.exe` (`Packed`).
mod packed {
    pub const SIZE: usize = 21_415_936;
    pub const PAYLOAD_SIZE: u32 = 12_782_080;
    pub const PAYLOAD_ID: u32 = 131;
    pub const ENTRY_POINT: u32 = 0x130bbfb;
    pub const ENTRY_POINT_SECTION: &str = ".rdata2";
    pub const PACKED_SECTIONS: [&str; 2] = [".text", ".rdata0"];
    pub const RUNTIME_SECTION: &str = ".rdata2";
    pub const EXCEPTION_TRIPLES: (usize, usize) = (64, 64);
}

fn sample(env: &str, default: &str) -> Option<(PathBuf, Vec<u8>)> {
    let path = PathBuf::from(std::env::var(env).unwrap_or_else(|_| default.to_string()));
    match std::fs::read(&path) {
        Ok(bytes) => Some((path, bytes)),
        Err(e) => {
            println!(
                "SKIP: {env} -> {} not readable ({e}); this gate tested nothing",
                path.display()
            );
            None
        }
    }
}

fn load(path: &Path, bytes: &[u8]) -> PeHeader {
    PeHeader::from_bytes(bytes)
        .unwrap_or_else(|e| panic!("{} must parse as a PE: {e}", path.display()))
}

/// `MinProtection`: the original sections are in the file, so the report is
/// almost entirely static — this is the mode the engine can answer for
/// without running anything.
#[test]
fn min_protection_sample_matches_every_recorded_value() {
    let Some((path, bytes)) = sample(
        "MIDA_VMPROTECT_MIN_SAMPLE",
        r"D:\Projects\lunlun\伦伦软件.exe",
    ) else {
        return;
    };
    assert_eq!(
        bytes.len(),
        min_protection::SIZE,
        "{} changed size — re-record the golden, do not relax the assert",
        path.display()
    );

    let pe = load(&path, &bytes);
    let detection = detect(&pe, &bytes).expect("must classify as VMProtect");
    assert_eq!(
        detection.kind,
        mida_packer_api::PackerKind::VmProtect(VmProtectMode::MinProtection),
        "evidence: {:?}",
        detection.render_evidence()
    );
    // The discriminator must be the measured one, not a name coincidence.
    let codes: Vec<&str> = detection.evidence.iter().map(|e| e.code).collect();
    assert!(codes.contains(&"notpaged-executable-section"), "{codes:?}");

    let r = analyze(&pe, &bytes);
    assert_eq!(r.mode, VmProtectMode::MinProtection);
    assert!(!r.requires_runtime_dump());
    assert!(r.entry_point_in_file);
    assert_eq!(r.runtime_sections, vec![min_protection::RUNTIME_SECTION]);
    assert!(r.packed_sections.is_empty());

    // The static fingerprint of the virtualised functions.
    assert_eq!(
        r.trampolines.len(),
        min_protection::TRAMPOLINES,
        "virtualised-function stub count moved"
    );
    for t in &r.trampolines {
        assert_eq!(t.target_section, min_protection::RUNTIME_SECTION);
        assert!(t.target_rva > t.stub_rva, "a stub must jump forward");
    }

    // VMProtect scrambles `.pdata` and moves the live table into `.vmp0`.
    assert_eq!(r.scrambled_pdata, Some(min_protection::PDATA_TRIPLES));
    let exc = r.exception_directory.as_ref().expect("exception directory");
    assert_eq!(exc.section, min_protection::EXCEPTION_SECTION);
    assert_eq!(
        (exc.plausible, exc.sampled),
        min_protection::EXCEPTION_TRIPLES
    );

    // The payload: in the file, so every byte of it can be pinned.
    let payload = r
        .large_resources
        .iter()
        .find(|x| x.name_id == Some(min_protection::PAYLOAD_ID))
        .expect("the RT_RCDATA payload must be reported");
    assert_eq!(payload.type_id, Some(RT_RCDATA));
    assert_eq!(payload.size, min_protection::PAYLOAD_SIZE);
    assert!(payload.fully_in_file(), "this mode carries the payload");
    assert_eq!(
        payload.sha256.as_deref(),
        Some(min_protection::PAYLOAD_SHA256)
    );
    assert_eq!(payload.magic.as_deref(), Some(min_protection::PAYLOAD_MAGIC));
    // Measured 8.0000 across every 4 MB window.
    let e = payload.entropy.expect("entropy");
    assert!((e - 8.0).abs() < 0.01, "payload entropy {e} is not saturated");
}

/// `Packed`: the code is not in the file at all, so the honest report says a
/// runtime image dump is required.  The payload is memory-only, which must be
/// reported as absent — **not** hashed from a truncated read.
#[test]
fn packed_sample_reports_absent_code_and_a_memory_only_payload() {
    let Some((path, bytes)) = sample("MIDA_VMPROTECT_PACKED_SAMPLE", r"D:\Projects\zz_test.exe")
    else {
        return;
    };
    assert_eq!(bytes.len(), packed::SIZE, "{} changed size", path.display());

    let pe = load(&path, &bytes);
    let detection = detect(&pe, &bytes).expect("must classify as VMProtect");
    assert_eq!(
        detection.kind,
        mida_packer_api::PackerKind::VmProtect(VmProtectMode::Packed)
    );

    let r = analyze(&pe, &bytes);
    assert_eq!(r.mode, VmProtectMode::Packed);
    assert!(r.requires_runtime_dump());
    assert_eq!(r.entry_point, packed::ENTRY_POINT);
    assert_eq!(
        r.entry_point_section.as_deref(),
        Some(packed::ENTRY_POINT_SECTION)
    );

    // Subtlety worth pinning: the entry point here is VMProtect's *own* loader
    // inside the packed section, so its bytes ARE in the file — measured, rva
    // `0x130bbfb` maps to file offset `0xbd0ffb` (praw `0x3400` + section
    // offset `0xbcdbfb`), and those 8 bytes occur exactly once in the whole
    // file.  What is absent is the *original* code.  A runtime-dump decision
    // keyed on the entry point would therefore be wrong; it must key on the
    // packed sections, which is what `requires_runtime_dump` does.
    assert!(
        r.entry_point_in_file,
        "VMProtect's loader entry lives inside .rdata2's file bytes"
    );
    assert_eq!(r.runtime_sections, vec![packed::RUNTIME_SECTION]);
    for name in packed::PACKED_SECTIONS {
        assert!(
            r.packed_sections.iter().any(|s| s == name),
            "{name} must be reported as carrying no file bytes; got {:?}",
            r.packed_sections
        );
    }
    // Nothing decodes because there is nothing to decode.  The report must say
    // *why*, which is asserted through the rendered text.
    assert!(r.trampolines.is_empty());
    let text = r.to_string();
    assert!(
        text.contains("runtime dump required"),
        "the empty stub list must be explained:\n{text}"
    );

    let exc = r.exception_directory.as_ref().expect("exception directory");
    assert_eq!(exc.section, packed::RUNTIME_SECTION);
    assert_eq!((exc.plausible, exc.sampled), packed::EXCEPTION_TRIPLES);

    let payload = r
        .large_resources
        .iter()
        .find(|x| x.name_id == Some(packed::PAYLOAD_ID))
        .expect("the RT_RCDATA payload must be reported even though it is not in the file");
    assert_eq!(payload.size, packed::PAYLOAD_SIZE);
    assert!(!payload.fully_in_file());
    assert_eq!(payload.bytes_in_file, 0);
    assert_eq!(
        payload.sha256, None,
        "a payload that is not in the file must not be hashed"
    );
}

/// Negative control: the Themida gate sample must *not* be claimed as
/// VMProtect.  Measured 0 of 63 Themida samples fire.
#[test]
fn themida_sample_is_never_claimed_as_vmprotect() {
    let Some((path, bytes)) = sample(
        "MIDA_VMPROTECT_THEMIDA_SAMPLE",
        r"D:\Projects\shiguang\时光一键宏.exe",
    ) else {
        return;
    };
    let pe = load(&path, &bytes);
    assert!(
        detect(&pe, &bytes).is_none(),
        "{} was claimed as VMProtect — the discriminator has a false positive",
        path.display()
    );
    // And the Themida markers really are present, so this is a meaningful
    // negative rather than a file that just failed to parse.
    let names: Vec<&str> = pe.sections.iter().map(section_name).collect();
    assert!(
        names.iter().any(|n| *n == ".winlice"),
        "expected a Themida sample; sections were {names:?}"
    );
}
