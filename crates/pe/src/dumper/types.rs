//! Shared types used across dumper submodules.
//!
//! Extracted from `dumper.rs`.

// -----------------------------------------------------------------------
// EarlySectionSnapshot
// -----------------------------------------------------------------------

/// Loader-initialized section bytes captured before application code runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlySectionSnapshot {
    /// Original PE section name.
    pub section_name: String,
    /// Section-relative virtual address in the image.
    pub rva: u32,
    /// Exact bytes read from the suspended target.
    pub bytes: Vec<u8>,
}

// -----------------------------------------------------------------------
// OEP / container restore policy
// -----------------------------------------------------------------------

/// How the final PE entry point is chosen after OEP observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OepPolicy {
    /// Prefer live MSVC CRT startup (cookie wrapper / `__scrt_common_main`).
    /// Explicit opt-in because signature scanning can match an earlier helper.
    Crt,
    /// Keep the frozen first decrypted `.text` RIP from post-attach observation.
    #[default]
    Captured,
    /// Force a specific image RVA as the PE entry point.
    Fixed(u32),
}

/// How SecurityCookie-encoded heap containers are restored in the dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainerRestoreMode {
    /// Detect containers, zero triples, do not install any restore stub.
    Off,
    /// After `__security_init_cookie` (patch CRT jmp) restore heaps then continue.
    /// Default: safe for MSVC CRT re-entry (启动??class).
    #[default]
    PostCrt,
    /// Pre-EP / TLS-style restore (breaks MSVC `_ioinit` on this sample).
    /// Experimental only.
    PreCrt,
}

// -----------------------------------------------------------------------
// Dump profile (GTO/AHK experimental isolation)
// -----------------------------------------------------------------------

/// High-level dump behaviour profile.
///
/// Default is the conservative Oreans/Themida path. GTO/AHK heap-graph,
/// container restore, and wrapper materialization are **never** auto-selected
/// by filename, SHA, or section names ??they require an explicit CLI opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DumpProfile {
    /// Conservative Oreans/Themida dump: PE image + OEP + import rebuild only.
    #[default]
    OreansClassic,
    /// Explicit GTO/AHK experimental path (heap graph, containers, wrappers).
    AhkGtoExperimental,
}

/// Capability flags derived from a [`DumpProfile`].
///
/// Pure data ??no process I/O. Callers pass these (or the profile) through
/// [`DumpOptions`]; the dumper must not re-guess the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpProfileCapabilities {
    pub capture_containers: bool,
    pub capture_heap_graph: bool,
    pub install_heap_bootstrap: bool,
    pub materialize_wrappers: bool,
    pub patch_wrapper_calls: bool,
    pub default_container_restore: ContainerRestoreMode,
}

/// Which of the seven high-risk experimental stages are enabled.
///
/// Pure stage plan for gating and synthetic tests ??no process dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExperimentalStagePlan {
    pub detect_containers: bool,
    pub detect_heap_globals: bool,
    pub scrub_uncaptured_heap_pointers: bool,
    pub install_heap_bootstrap: bool,
    pub materialize_image_iat_wrappers: bool,
    pub materialize_fill_code_refs: bool,
    pub patch_wrapper_iat_call_sites: bool,
}

impl DumpProfile {
    /// Resolve profile capabilities (pure function).
    pub fn capabilities(self) -> DumpProfileCapabilities {
        match self {
            DumpProfile::OreansClassic => DumpProfileCapabilities {
                capture_containers: false,
                capture_heap_graph: false,
                install_heap_bootstrap: false,
                materialize_wrappers: false,
                patch_wrapper_calls: false,
                default_container_restore: ContainerRestoreMode::Off,
            },
            DumpProfile::AhkGtoExperimental => DumpProfileCapabilities {
                capture_containers: true,
                capture_heap_graph: true,
                install_heap_bootstrap: true,
                materialize_wrappers: true,
                patch_wrapper_calls: true,
                default_container_restore: ContainerRestoreMode::PostCrt,
            },
        }
    }

    /// Stage plan used by `dump_process` to gate experimental work.
    pub fn stage_plan(self) -> ExperimentalStagePlan {
        self.capabilities().stage_plan()
    }
}

impl DumpProfileCapabilities {
    /// Map capabilities onto the seven gated experimental call sites.
    pub fn stage_plan(self) -> ExperimentalStagePlan {
        ExperimentalStagePlan {
            detect_containers: self.capture_containers,
            detect_heap_globals: self.capture_heap_graph,
            scrub_uncaptured_heap_pointers: self.capture_heap_graph || self.capture_containers,
            install_heap_bootstrap: self.install_heap_bootstrap,
            materialize_image_iat_wrappers: self.materialize_wrappers,
            materialize_fill_code_refs: self.materialize_wrappers,
            patch_wrapper_iat_call_sites: self.patch_wrapper_calls,
        }
    }

    /// True when any GTO/AHK experimental capability is enabled.
    pub fn any_experimental(self) -> bool {
        self.capture_containers
            || self.capture_heap_graph
            || self.install_heap_bootstrap
            || self.materialize_wrappers
            || self.patch_wrapper_calls
    }
}

impl ExperimentalStagePlan {
    /// True when every high-risk stage is disabled (OreansClassic).
    pub fn all_disabled(self) -> bool {
        !self.detect_containers
            && !self.detect_heap_globals
            && !self.scrub_uncaptured_heap_pointers
            && !self.install_heap_bootstrap
            && !self.materialize_image_iat_wrappers
            && !self.materialize_fill_code_refs
            && !self.patch_wrapper_iat_call_sites
    }

    /// True when every high-risk stage is enabled (AhkGtoExperimental).
    pub fn all_enabled(self) -> bool {
        self.detect_containers
            && self.detect_heap_globals
            && self.scrub_uncaptured_heap_pointers
            && self.install_heap_bootstrap
            && self.materialize_image_iat_wrappers
            && self.materialize_fill_code_refs
            && self.patch_wrapper_iat_call_sites
    }
}

// -----------------------------------------------------------------------
// DumpProcessReport
// -----------------------------------------------------------------------

/// Evidence returned after a dump candidate has been fully serialized.
///
/// The report is deliberately separate from [`DumpOptions`]: callers can
/// distinguish a requested IAT reconstruction from evidence that was actually
/// collected, and can gate on the immutable per-slot report without parsing a
/// log or guessing from the output file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpProcessReport {
    /// Whether the caller requested live IAT reconstruction.
    pub fix_imports_requested: bool,
    /// Whether an IAT recovery report was produced.
    pub iat_evidence_present: bool,
    /// Whether the produced IAT report passed the strict completeness gate.
    pub iat_evidence_complete: bool,
    /// The immutable IAT evidence, when `fix_imports` was requested.
    pub iat_report: Option<crate::iat_completeness::IatRecoveryReport>,
    /// Whether the initial runtime TLS data directory was present.
    pub tls_evidence_present: bool,
    /// Whether the immutable runtime TLS observation had no blocker.
    pub tls_evidence_complete: bool,
    /// Immutable runtime TLS observation captured before dump mutation.
    pub tls_report: crate::tls_observation::TlsObservationReport,
    /// Immutable runtime base-relocation observation captured before dump mutation.
    pub relocation_evidence_present: bool,
    /// Whether the immutable runtime relocation observation had no blocker.
    pub relocation_evidence_complete: bool,
    /// Immutable runtime base-relocation observation.
    pub relocation_report: crate::relocation_observation::RelocationObservationReport,
    /// Number of bytes in the final candidate written to disk.
    pub output_size: usize,
}

// -----------------------------------------------------------------------
// DumpOptions
// -----------------------------------------------------------------------

/// Options controlling the dump process.
#[derive(Debug, Clone)]
pub struct DumpOptions {
    /// Preferred load address of the target executable.
    pub image_base: u64,

    /// RVA of the original entry point.
    pub entry_point: u32,

    /// If `true`, reconstruct the import table from the live IAT.
    pub fix_imports: bool,

    /// If `true`, restore `.rdata`/`.data` sections from the target.
    pub create_data_sections: bool,

    /// If `true`, remove sections that are no longer needed (compression
    /// leftovers, Themida-specific sections).
    pub shrink: bool,

    /// Path where the dumped executable will be written.
    pub output_path: std::path::PathBuf,

    /// Optional IAT location override.  When `Some`, the dump uses this
    /// address and size instead of looking up the IAT data directory in
    /// the PE header.  This is needed for protectors (e.g. Themida) that
    /// strip or obfuscate the PE header's IAT directory.
    pub iat_location: Option<(usize, usize)>,

    /// Additional IAT locations (virtual addresses) referenced by code.
    /// These will be filled with the same Hint/Name RVAs as the primary IAT.
    /// Used to fix the "dual IAT" problem where code uses mov+call pattern.
    pub additional_iat_locations: Vec<usize>,

    /// Original (disk) path of the protected executable.  When present,
    /// the dumper reads the on-disk PE header to recover fields that may
    /// have been corrupted in-memory by the protector's VM exit
    /// (FileHeader.Characteristics, Subsystem, etc.).  Falls back to the
    /// in-memory header if the file is missing or unparseable.
    pub executable_path: Option<std::path::PathBuf>,

    /// Loader-initialized section baselines captured before the target's main
    /// thread was resumed. Empty for traditional debugging and other samples.
    pub early_section_snapshots: Vec<EarlySectionSnapshot>,

    /// Container restore policy (see [`ContainerRestoreMode`]).
    /// When the user does not pass `--container-restore`, CLI sets this from
    /// [`DumpProfileCapabilities::default_container_restore`].
    pub container_restore: ContainerRestoreMode,

    /// Dump behaviour profile. Default [`DumpProfile::OreansClassic`].
    /// Must be passed explicitly from CLI / callers ??never re-guessed here.
    pub profile: DumpProfile,

    /// Authoritative MSVC SecurityCookie RVA from offline CRT resolve.
    /// When set with [`Self::security_cookie_complement_rva`], the dumper plants
    /// this site and must not re-scan for cookie/complement pairs.
    pub security_cookie_rva: Option<u32>,

    /// Authoritative MSVC SecurityCookie complement RVA (paired with
    /// [`Self::security_cookie_rva`]).
    pub security_cookie_complement_rva: Option<u32>,

    /// R1-D/E: emit final PE via pure rebuild (`plan_from_host_dump` /
    /// `rebuild_pe_image`) instead of legacy `write_output_file`.
    /// Default false keeps production dump behaviour unchanged.
    /// R1-E preserves host section VAs and carries host data directories
    /// (import/IAT/TLS content). Typed import rebind is still not in this path.
    pub pure_rebuild: bool,

    /// Heap-global / hot-root capture policy. Empty + [`DumpProfile::AhkGtoExperimental`]
    /// resolves to built-in AHK/GTO defaults; OreansClassic leaves capture empty
    /// (stages still gated by profile). Future: case manifest / plugin fill this.
    pub capture_policy: super::capture_policy::DumpCapturePolicy,
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn default_profile_is_oreans_classic() {
        assert_eq!(DumpProfile::default(), DumpProfile::OreansClassic);
    }

    #[test]
    fn oreans_classic_disables_all_gto_capabilities() {
        let caps = DumpProfile::OreansClassic.capabilities();
        assert!(!caps.capture_containers);
        assert!(!caps.capture_heap_graph);
        assert!(!caps.install_heap_bootstrap);
        assert!(!caps.materialize_wrappers);
        assert!(!caps.patch_wrapper_calls);
        assert!(!caps.any_experimental());
        assert_eq!(caps.default_container_restore, ContainerRestoreMode::Off);
    }

    #[test]
    fn ahk_gto_experimental_enables_capabilities() {
        let caps = DumpProfile::AhkGtoExperimental.capabilities();
        assert!(caps.capture_containers);
        assert!(caps.capture_heap_graph);
        assert!(caps.install_heap_bootstrap);
        assert!(caps.materialize_wrappers);
        assert!(caps.patch_wrapper_calls);
        assert!(caps.any_experimental());
        assert_eq!(
            caps.default_container_restore,
            ContainerRestoreMode::PostCrt
        );
    }

    #[test]
    fn oreans_classic_stage_plan_disables_all_seven() {
        let plan = DumpProfile::OreansClassic.stage_plan();
        assert!(plan.all_disabled());
        assert!(!plan.detect_containers);
        assert!(!plan.detect_heap_globals);
        assert!(!plan.scrub_uncaptured_heap_pointers);
        assert!(!plan.install_heap_bootstrap);
        assert!(!plan.materialize_image_iat_wrappers);
        assert!(!plan.materialize_fill_code_refs);
        assert!(!plan.patch_wrapper_iat_call_sites);
    }

    #[test]
    fn ahk_gto_stage_plan_enables_all_seven() {
        let plan = DumpProfile::AhkGtoExperimental.stage_plan();
        assert!(plan.all_enabled());
        assert!(plan.detect_containers);
        assert!(plan.detect_heap_globals);
        assert!(plan.scrub_uncaptured_heap_pointers);
        assert!(plan.install_heap_bootstrap);
        assert!(plan.materialize_image_iat_wrappers);
        assert!(plan.materialize_fill_code_refs);
        assert!(plan.patch_wrapper_iat_call_sites);
    }
}

// -----------------------------------------------------------------------
// RemoteModule (for Pass 1)
// -----------------------------------------------------------------------

/// Information about a loaded module in the target process.
/// Corresponds to `TRemoteModule` in `Dumper.pas`.
#[derive(Debug, Clone)]
pub struct RemoteModule {
    /// Base address of the module in the target's virtual address space.
    pub(crate) base: u64,
    /// End of the module (`base + size`).
    pub(crate) end_off: u64,
    /// Exact PE SizeOfImage (authoritative image span). Toolhelp modBaseSize
    /// can under-report the trailing section alignment page; PE SizeOfImage is
    /// the loader-truth end for module attribution.
    pub(crate) size_of_image: u64,
    /// Module name (lowercase, e.g. `"kernel32.dll"`).
    pub(crate) name: String,
    /// Export table: address ??function name (or `"#ordinal"`).
    pub(crate) exports: std::collections::HashMap<u64, String>,
    /// Forward entries: `"module.function"` ??export address in this module.
    #[allow(dead_code)]
    pub(crate) forwards: Vec<(String, u64)>,
}

/// A candidate resolution for one IAT slot.
#[derive(Debug, Clone)]
pub(crate) struct ResolutionCandidate {
    /// The address in the target process that identifies the export.
    pub(crate) address: u64,
    /// Index into `all_modules` identifying which module owns this export.
    pub(crate) module_index: usize,
}

/// State for one IAT slot during reconstruction.
#[derive(Debug)]
pub(crate) struct IatSlot {
    /// All valid resolutions for this slot.
    pub(crate) candidates: Vec<ResolutionCandidate>,
    /// Immutable pointer value captured from the live read before PASS2.
    pub(crate) observed_value: Option<u64>,
    /// Pointer value written into the reconstructed IAT buffer by PASS2.
    pub(crate) rebuilt_value: Option<u64>,
    /// Index into `candidates` of the chosen resolution, or `None` if
    /// unresolved.
    pub(crate) chosen: Option<usize>,
    /// `true` if the slot value is zero (group separator).
    pub(crate) is_zero: bool,
    /// Fail-closed state carried into the public recovery report.
    pub(crate) status: crate::iat_completeness::IatSlotStatus,
    /// Deterministic root-cause reason for a non-`Resolved` slot, carried into
    /// the public recovery report.
    pub(crate) unresolved_reason: Option<crate::iat_completeness::IatUnresolvedReason>,
}

// -----------------------------------------------------------------------
// is_api_address
// -----------------------------------------------------------------------

/// Check whether an address falls within a known module's export table.
///
/// Corresponds to `TDumper.IsAPIAddress` in `Dumper.pas`.
pub(crate) fn is_api_address(modules: &[RemoteModule], address: u64) -> bool {
    for m in modules {
        if address > m.base && address < m.end_off {
            return m.exports.contains_key(&address);
        }
    }
    false
}
