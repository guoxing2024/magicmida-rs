//! Canonical, cross-language generic dump-verification gate.
//!
//! This module is the **single source of truth** for the generic gate rules.
//! The Rust pipeline ([`crate::unpacker::generic::generic_unpack`]) and the
//! Python pipeline (`tools/generic_unpack.py`) implement the **same** pure
//! function with identical inputs, names, and failure strings.  Both load the
//! same JSON test vectors (`gate_vectors.json`) to prove parity — see
//! `tests/gate_vectors.rs` and `tools/test_generic_gate.py`.
//!
//! ## Contract
//!
//! Inputs are a fixed set of booleans ([`GenericGateInputs`]) computed by each
//! implementation from its own PE representation:
//!
//! | input             | definition (identical Rust/Python)                          |
//! |-------------------|-------------------------------------------------------------|
//! | `text_present`    | any section whose name starts with `.text`                  |
//! | `text_has_raw`    | that section's on-disk raw size > 0                         |
//! | `text_looks_code` | heuristic density check — **warning metric only**          |
//! | `large_rx_present`| any section that is executable AND `virtual_size >= 0x100000`|
//! | `large_rx_has_raw`| every present large-RX section has raw size > 0             |
//! | `has_ahk_export`  | an export name is in [`AHK_EXPORT_NAMES`]                  |
//!
//! ## Profiles
//!
//! | profile          | required gates                                              |
//! |-----------------|-------------------------------------------------------------|
//! | `PackerAgnostic` | `text_present` AND `text_has_raw` (large RX is **not** a gate) |
//! | `AhkLauncher`    | above AND (`large_rx_present` OR `has_ahk_export`) AND `large_rx_has_raw` |
//!
//! `text_looks_code` is **never** a hard gate; a non-code-looking `.text`
//! only appends a warning.  This corrects the prior Python behaviour that
//! hard-failed on it.
//!
//! ## Production input-source difference (documented, intentional)
//!
//! The pure [`validate_generic_dump`] function is identical across Rust and
//! Python — same inputs, same decision, same strings.  However, the **source**
//! of one input differs by pipeline:
//!
//! - `text_looks_code` requires reading `.text` bytes to run a density
//!   heuristic.  The Python pipeline reads the live/disk image content it
//!   already has, so it computes a real `text_looks_code` and can emit the
//!   warning.  The Rust pipeline does not read `.text` bytes here (it would
//!   need the on-disk file), so [`gate_inputs_from_pe`] defaults
//!   `text_looks_code = true` and therefore never emits the warning.
//! - This is acceptable precisely because `text_looks_code` is a **warning
//!   metric only**: a Rust `true` default can never mask a real hard-gate
//!   failure (the hard gates are `text_present`/`text_has_raw`/​large-RX).
//! - All other inputs are computed identically from the parsed PE in both
//!   pipelines.
//!
//! The contract is: **the pure gate's decision is identical for identical
//! inputs**; the production pipelines may feed a different `text_looks_code`
//! value, but that only affects whether the warning is emitted, never `pass`.
//! See `text_looks_code_source_difference_warning_only`.
//!
//! The gate is pure: no I/O, no processes (`target_process_starts = 0`).

use mida_pe::PeHeader;

/// Export-name set that satisfies the AHK-launcher gate's `has_ahk_export`
/// input.  **Identical** literal set in Rust and Python.
pub const AHK_EXPORT_NAMES: &[&str] = &["AhkExec", "AHKEXEC", "AddScript", "ADDSCRIPT"];

/// `true` iff `name` is a canonical AHK export name (exact, case-sensitive
/// match against [`AHK_EXPORT_NAMES`]).  Rust and Python use the exact same
/// matching semantics.
#[must_use]
pub fn is_ahk_export_name(name: &str) -> bool {
    AHK_EXPORT_NAMES.contains(&name)
}

/// Which set of hard gates to enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericGateProfile {
    /// Packer-agnostic baseline: only `.text`-present-with-raw is required.
    PackerAgnostic,
    /// AutoHotkey-derived packed launcher: additionally requires a large RX
    /// section (≥ 0x100000) with raw data, **or** an AHK export.  Explicit
    /// opt-in; not a generic global gate.
    AhkLauncher,
}

/// Canonical boolean inputs to the pure gate.  Both implementations compute
/// these from their PE representation and feed them to
/// [`validate_generic_dump`] so the decision is identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericGateInputs {
    /// `.text` section present.
    pub text_present: bool,
    /// `.text` section has on-disk raw data (`raw_size > 0`).
    pub text_has_raw: bool,
    /// Heuristic: `.text` looks like code.  **Warning metric only** — never a
    /// hard gate.
    pub text_looks_code: bool,
    /// At least one large RX section present.
    pub large_rx_present: bool,
    /// Every present large-RX section has raw data.
    pub large_rx_has_raw: bool,
    /// An AHK export name ([`AHK_EXPORT_NAMES`]) is present.
    pub has_ahk_export: bool,
    /// XC-7-A: shell section residue present (`.winlice`/`.boot`/`.themida`,
    /// or an all-virtual >=1 MiB non-standard section). Dumps of protected
    /// inputs must not carry shell remnants (S1 standard).
    pub shell_sections_present: bool,
}

/// Result of running the generic gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericGateResult {
    /// Profile evaluated.
    pub profile: GenericGateProfile,
    /// Overall pass/fail for the chosen profile.
    pub pass: bool,
    /// Failing hard gates (empty on pass).  Literals are **identical** in the
    /// Python implementation.
    pub failures: Vec<&'static str>,
    /// Soft warnings (e.g. `.text` does not look like code).  Never affects
    /// `pass`.
    pub warnings: Vec<&'static str>,
    /// Echoed inputs for diagnostics.
    pub inputs: GenericGateInputs,
}

impl GenericGateResult {
    /// `true` iff all required gates passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.pass
    }
}

/// Pure gate: evaluate the canonical rules over canonical inputs.
///
/// `text_looks_code` is a **warning metric only** — it never appends to
/// `failures`.  This is the parity fix for the Python side, which previously
/// hard-failed on it.
#[must_use]
pub fn validate_generic_dump(
    inputs: GenericGateInputs,
    profile: GenericGateProfile,
) -> GenericGateResult {
    let mut failures: Vec<&'static str> = Vec::new();
    let mut warnings: Vec<&'static str> = Vec::new();

    if !inputs.text_present {
        failures.push(".text section missing");
    }
    if inputs.shell_sections_present {
        failures.push("shell section residue present (.winlice/.boot/.themida)");
    }
    if !inputs.text_has_raw {
        failures.push(".text section has no raw data");
    }
    if !inputs.text_looks_code {
        warnings.push(".text section does not look like code (warning)");
    }

    match profile {
        GenericGateProfile::PackerAgnostic => {
            // No pack-specific gates; large RX is explicitly NOT a gate here.
        }
        GenericGateProfile::AhkLauncher => {
            if !(inputs.large_rx_present || inputs.has_ahk_export) {
                failures.push("no large RX section (>=0x100000) and no AhkExec export");
            }
            if !inputs.large_rx_has_raw {
                failures.push("large RX section present without raw data");
            }
        }
    }

    let pass = failures.is_empty();
    GenericGateResult {
        profile,
        pass,
        failures,
        warnings,
        inputs,
    }
}

/// Compute canonical [`GenericGateInputs`] from a parsed [`PeHeader`] plus a
/// caller-supplied `has_ahk_export` flag (the Rust pipeline does not parse
/// exports here; the Python pipeline does).  The booleans are computed with
/// the **same** definitions the Python side uses.
#[must_use]
pub fn gate_inputs_from_pe(pe: &PeHeader, has_ahk_export: bool) -> GenericGateInputs {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
    let is_exec = |s: &mida_pe::PeSection| (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    let is_large_rx = |s: &mida_pe::PeSection| is_exec(s) && s.virtual_size >= 0x100000;

    // .text detection with a name-erasure fallback: packers such as
    // Themida/WinLicense wipe section names to spaces ("        ") while the
    // code section stays the first executable section with the CODE flag.
    // Treat an all-blank-named executable section as the code section so the
    // gate does not reject a structurally valid dump.
    let text = pe
        .sections
        .iter()
        .find(|s| s.name.starts_with(".text"))
        .or_else(|| {
            pe.sections.iter().find(|s| {
                s.name.trim().is_empty()
                    && is_exec(s)
                    && (s.characteristics & IMAGE_SCN_CNT_CODE) != 0
                    && s.virtual_size > 0
            })
        });
    let text_present = text.is_some();
    let text_has_raw = text.is_some_and(|s| s.raw_size > 0);

    // Rust cannot cheaply read the .text bytes for a density heuristic without
    // the on-disk file; the Python side computes this from memory content.
    // Default to `true` so the warning is only ever emitted by the Python
    // pipeline where the bytes are available.  The contract: text_looks_code
    // is a warning, never a hard gate, so a Rust `true` default never masks a
    // real failure.
    let text_looks_code = true;

    let large_rx: Vec<&mida_pe::PeSection> =
        pe.sections.iter().filter(|s| is_large_rx(s)).collect();
    let large_rx_present = !large_rx.is_empty();
    let large_rx_has_raw = large_rx.iter().all(|s| s.raw_size > 0);

    // XC-7-A: shell residue = Themida-named sections, or all-virtual (raw=0)
    // large sections with non-standard names (>= 1 MiB virtual). A clean dump
    // must have neither.
    let shell_named = |s: &mida_pe::PeSection| {
        let lower = s.name.to_lowercase();
        lower.contains(".winlice")
            || lower.contains(".boot")
            || lower.contains(".themida")
            || lower.contains(".winlic")
    };
    let all_virtual_large = |s: &mida_pe::PeSection| {
        s.raw_size == 0
            && s.virtual_size >= 0x100000
            && !s.name.starts_with(".text")
            && !s.name.starts_with(".data")
            && !s.name.starts_with(".rdata")
    };
    let shell_sections_present = pe
        .sections
        .iter()
        .any(|s| shell_named(s) || all_virtual_large(s));

    GenericGateInputs {
        text_present,
        text_has_raw,
        text_looks_code,
        large_rx_present,
        large_rx_has_raw,
        has_ahk_export,
        shell_sections_present,
    }
}

/// Marker error raised by the generic pipeline when a hard gate fails.
///
/// The CLI maps this to exit code `2` (distinct from `1` for other fatal
/// errors) so automation can distinguish "dump produced but failed gates"
/// from "the pipeline could not run".
#[derive(Debug, thiserror::Error)]
#[error("generic gate FAILED: {failures:?}")]
pub struct GenericGateFailure {
    pub failures: Vec<&'static str>,
}

impl GenericGateFailure {
    #[must_use]
    pub fn from_result(r: &GenericGateResult) -> Self {
        Self {
            failures: r.failures.clone(),
        }
    }
}

/// Evaluate the gate from a parsed PE and return `Ok(())` on pass or
/// `Err(GenericGateFailure)` on fail.  This is the Result-shaped entry point
/// the generic pipeline calls after dumping.
pub fn check_generic_dump(
    pe: &PeHeader,
    profile: GenericGateProfile,
    has_ahk_export: bool,
) -> Result<(), GenericGateFailure> {
    let inputs = gate_inputs_from_pe(pe, has_ahk_export);
    let r = validate_generic_dump(inputs, profile);
    if r.passed() {
        Ok(())
    } else {
        Err(GenericGateFailure::from_result(&r))
    }
}

// ---------------------------------------------------------------------------
// Tests — pure gate decision logic (no process, no I/O)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mida_pe::PeSection;

    fn inputs() -> GenericGateInputs {
        GenericGateInputs {
            text_present: true,
            text_has_raw: true,
            text_looks_code: true,
            large_rx_present: true,
            large_rx_has_raw: true,
            has_ahk_export: false,
            shell_sections_present: false,
        }
    }

    const AGNOSTIC: GenericGateProfile = GenericGateProfile::PackerAgnostic;
    const AHK: GenericGateProfile = GenericGateProfile::AhkLauncher;

    #[test]
    fn packer_agnostic_passes_with_text_only() {
        let mut i = inputs();
        i.large_rx_present = false;
        let r = validate_generic_dump(i, AGNOSTIC);
        assert!(r.passed());
        assert!(r.inputs.text_has_raw);
        assert!(!r.inputs.large_rx_present);
        assert!(r.failures.is_empty());
    }

    #[test]
    fn packer_agnostic_fails_without_text() {
        let mut i = inputs();
        i.text_present = false;
        let r = validate_generic_dump(i, AGNOSTIC);
        assert!(!r.passed());
        assert!(r
            .failures
            .iter()
            .any(|f| f.contains(".text section missing")));
    }

    #[test]
    fn packer_agnostic_fails_when_text_has_no_raw() {
        let mut i = inputs();
        i.text_has_raw = false;
        let r = validate_generic_dump(i, AGNOSTIC);
        assert!(!r.passed());
        assert!(r.failures.iter().any(|f| f.contains("no raw data")));
    }

    /// text_looks_code=false is a WARNING, not a failure, under both profiles.
    #[test]
    fn text_looks_code_is_warning_not_failure() {
        let mut i = inputs();
        i.text_looks_code = false;
        let r = validate_generic_dump(i, AGNOSTIC);
        assert!(
            r.passed(),
            "must still pass — text_looks_code is warning only"
        );
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("does not look like code")));
        assert!(r.failures.is_empty());
    }

    #[test]
    fn ahk_launcher_passes_with_large_rx_raw() {
        let r = validate_generic_dump(inputs(), AHK);
        assert!(r.passed());
        assert!(r.inputs.large_rx_present);
        assert!(r.inputs.large_rx_has_raw);
    }

    #[test]
    fn ahk_launcher_passes_with_ahk_export_and_no_large_rx() {
        let mut i = inputs();
        i.large_rx_present = false;
        i.has_ahk_export = true;
        let r = validate_generic_dump(i, AHK);
        assert!(r.passed());
        assert!(r.inputs.has_ahk_export);
        assert!(!r.inputs.large_rx_present);
        assert!(r.inputs.large_rx_has_raw, "vacuously true");
    }

    #[test]
    fn ahk_launcher_fails_without_large_rx_or_export() {
        let mut i = inputs();
        i.large_rx_present = false;
        let r = validate_generic_dump(i, AHK);
        assert!(!r.passed());
        assert!(r.failures.iter().any(|f| f.contains("no large RX")));
    }

    #[test]
    fn ahk_launcher_fails_when_large_rx_has_no_raw() {
        let mut i = inputs();
        i.large_rx_has_raw = false;
        let r = validate_generic_dump(i, AHK);
        assert!(!r.passed());
        assert!(r.failures.iter().any(|f| f.contains("without raw data")));
    }

    #[test]
    fn gate_failure_carries_failure_list() {
        let mut i = inputs();
        i.text_present = false;
        let r = validate_generic_dump(i, AGNOSTIC);
        let err = GenericGateFailure::from_result(&r);
        assert!(!err.failures.is_empty());
        assert!(format!("{err}").contains("generic gate FAILED"));
    }

    #[test]
    fn check_generic_dump_ok_on_pass_err_on_fail() {
        let mut pass = inputs();
        pass.large_rx_present = false;
        assert!(check_generic_dump_pe(pass, AGNOSTIC).is_ok());

        let mut fail = inputs();
        fail.text_present = false;
        let err = check_generic_dump_pe(fail, AGNOSTIC).expect_err("missing .text must fail");
        assert!(!err.failures.is_empty());
        let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(err);
        assert!(boxed.downcast_ref::<GenericGateFailure>().is_some());
    }

    /// Helper: run check_generic_dump over a synthetic PeHeader built from the
    /// given inputs (mirrors what the real pipeline does).
    fn check_generic_dump_pe(
        i: GenericGateInputs,
        profile: GenericGateProfile,
    ) -> Result<(), GenericGateFailure> {
        use mida_pe::{
            ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders,
            ImageOptionalHeader, PeHeader, PeSection,
        };
        const EXEC: u32 = 0x2000_0000;
        let mut secs: Vec<PeSection> = Vec::new();
        if i.text_present {
            let raw = if i.text_has_raw { 0x200 } else { 0 };
            secs.push(mk_sec(".text", 0x1000, raw, EXEC));
        }
        if i.large_rx_present {
            let raw = if i.large_rx_has_raw { 0x200000 } else { 0 };
            secs.push(mk_sec(".big", 0x200000, raw, EXEC));
        }
        if secs.is_empty() {
            secs.push(mk_sec(".rdata", 0x1000, 0x200, 0));
        }
        let pe = PeHeader {
            dos_header: ImageDosHeader {
                e_magic: 0x5A4D,
                e_lfanew: 0x80,
            },
            nt_headers: ImageNtHeaders {
                signature: 0x4550,
                file_header: ImageFileHeader {
                    machine: 0x8664,
                    number_of_sections: secs.len() as u16,
                    time_date_stamp: 0,
                    size_of_optional_header: 0xF0,
                    characteristics: 0x22,
                },
                optional_header: ImageOptionalHeader {
                    magic: 0x20B,
                    major_linker_version: 14,
                    minor_linker_version: 0,
                    size_of_code: 0,
                    size_of_initialized_data: 0,
                    size_of_uninitialized_data: 0,
                    address_of_entry_point: 0x1000,
                    base_of_code: 0x1000,
                    base_of_data: None,
                    image_base: 0x140000000,
                    section_alignment: 0x1000,
                    file_alignment: 0x200,
                    major_operating_system_version: 6,
                    minor_operating_system_version: 0,
                    major_image_version: 0,
                    minor_image_version: 0,
                    major_subsystem_version: 6,
                    minor_subsystem_version: 0,
                    win32_version_value: 0,
                    size_of_image: 0x10000,
                    size_of_headers: 0x200,
                    check_sum: 0,
                    subsystem: 3,
                    dll_characteristics: 0,
                    size_of_stack_reserve: 0x100000,
                    size_of_stack_commit: 0x1000,
                    size_of_heap_reserve: 0x100000,
                    size_of_heap_commit: 0x1000,
                    loader_flags: 0,
                    number_of_rva_and_sizes: 16,
                    data_directory: [ImageDataDirectory::default(); 16],
                },
            },
            sections: secs,
            image_base: 0x140000000,
            entry_point: 0x1000,
            is_64bit: true,
            file_alignment: 0x200,
            section_alignment: 0x1000,
        };
        check_generic_dump(&pe, profile, i.has_ahk_export)
    }

    fn mk_sec(name: &str, vsize: u32, raw: u32, chars: u32) -> PeSection {
        use mida_pe::ImageSectionHeader;
        let mut nb = [0u8; 8];
        let b = name.as_bytes();
        nb[..b.len().min(8)].copy_from_slice(&b[..b.len().min(8)]);
        PeSection {
            header: ImageSectionHeader {
                name: nb,
                virtual_size: vsize,
                virtual_address: 0x1000,
                size_of_raw_data: raw,
                pointer_to_raw_data: 0x200,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: chars,
            },
            name: name.to_string(),
            virtual_address: 0x1000,
            virtual_size: vsize,
            raw_offset: 0x200,
            raw_size: raw,
            characteristics: chars,
            extra_data: None,
        }
    }

    #[test]
    fn ahk_name_set_is_canonical() {
        assert!(is_ahk_export_name("AhkExec"));
        assert!(is_ahk_export_name("AHKEXEC"));
        assert!(is_ahk_export_name("AddScript"));
        assert!(is_ahk_export_name("ADDSCRIPT"));
        assert!(!is_ahk_export_name("ahkexec")); // exact match, case-sensitive
        assert!(!is_ahk_export_name("Foo"));
    }

    /// Production input-source difference: the pure gate is identical, but
    /// the Rust pipeline's `gate_inputs_from_pe` defaults `text_looks_code`
    /// to `true` (it does not read `.text` bytes), whereas the Python
    /// pipeline computes a real value.  Because `text_looks_code` is a
    /// **warning metric only**, this difference can never flip `pass` — it
    /// only affects whether the warning is emitted.  This test pins that
    /// invariant: identical hard-gate inputs with differing
    /// `text_looks_code` produce the same `pass`/`failures`.
    #[test]
    fn text_looks_code_source_difference_warning_only() {
        let mut base = inputs();
        base.large_rx_present = false;
        let rust_inputs = base; // gate_inputs_from_pe would set text_looks_code=true
        let mut py_inputs = base;
        py_inputs.text_looks_code = false; // Python computed "not code"

        let rust = validate_generic_dump(rust_inputs, AGNOSTIC);
        let py = validate_generic_dump(py_inputs, AGNOSTIC);

        // Identical pass / failures — the hard-gate decision is the same.
        assert_eq!(rust.pass, py.pass);
        assert_eq!(rust.failures, py.failures);
        // Only the warning differs: Rust emits none, Python emits the warning.
        assert!(rust.warnings.is_empty());
        assert!(py
            .warnings
            .iter()
            .any(|w| w.contains("does not look like code")));
    }

    /// `text_looks_code=false` must NOT turn into a failure under the
    /// AhkLauncher profile either (regression guard: the warning stays a
    /// warning even when other AHK gates fail).
    #[test]
    fn text_looks_code_warning_stays_warning_with_ahk_failures() {
        let mut i = inputs();
        i.text_looks_code = false;
        i.large_rx_present = false; // forces an AHK hard failure
        let r = validate_generic_dump(i, AHK);
        assert!(!r.pass, "AHK gate must still fail on missing large RX");
        // The text-look issue appears in warnings, NOT failures.
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("does not look like code")));
        assert!(!r
            .failures
            .iter()
            .any(|f| f.contains("does not look like code")));
        assert!(r.failures.iter().any(|f| f.contains("no large RX")));
    }
}
