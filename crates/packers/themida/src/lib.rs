//! # mida-packers-themida
//!
//! Themida unpacker implementation.
//!
//! This crate implements the packer-specific logic for detecting and removing
//! Themida protections: virtualised code, obfuscated stubs, anti-debug tricks,
//! and import protection. It is built on top of the generic debugging
//! infrastructure in `mida-core`.
//!
//! ## Modules
//!
//! - [`version`]        — Themida version identification and section heuristics.
//! - [`init`]           — PE initialisation (maps `InitPEDetails` and `TMInit`).
//! - [`common`]         — shared mutable state carried through the unpack pipeline.
//! - [`antiantidebug`]  — anti-anti-debug strategies: NtSetInformationThread,
//!                         NtQueryInformationProcess, KiFastSystemCall hook,
//!                         and ScyllaHide integration.
//! - [`error`]          — error types for all fallible operations.
//!
//! Future packer implementations (VMProtect, Enigma, …) will live in sibling
//! crates under `crates/packers/`.

pub mod antiantidebug;
pub mod binaries;
pub mod common;
pub mod error;
pub mod guard;
pub mod iat;
pub mod init;
pub mod oep;
pub mod postprocess;
pub mod text_tracer;
pub mod trace_imports;
pub mod version;

// Re-export the primary types so callers can do `use mida_packers_themida::…`
pub use antiantidebug::{
    handle_nt_query_information_process,
    handle_nt_set_information_thread, inject_scylla_hide,
    ScyllaHideConfig,
};
#[cfg(target_arch = "x86")]
pub use antiantidebug::{
    handle_kifast_syscall, install_kifast_syscall_hook,
    get_nt_qip_syscall_number,
};
pub use binaries::{expected_hook_hash, expected_injector_hash, verify_sha256};
pub use common::ThemidaState;
pub use error::ThemidaError;
pub use guard::{
    install_code_section_guard, install_iat_guard, is_guarded_address,
    process_guarded_access, process_iat_monitoring_access,
    remove_code_section_guard, re_guard_iat, restore_code_section_guard,
    switch_to_iat_monitoring, temporary_un_guard_iat, GuardAccessResult,
};
pub use iat::{
    detect_compiler, determine_iat_address, fix_iat, fixup_api_call_sites,
    CompilerHint, IatFixStrategy, IatLocation,
};
pub use init::{init_pe_details, locate_themida_section, ThemidaPeInfo};
pub use oep::{
    find_real_oep_by_scanning, find_real_oep_in_bytes, handle_tls_callbacks, is_oep_virtualized,
    restore_stolen_oep_msvc6, restore_stolen_oep_msvc9_dll, try_find_correct_oep,
    try_find_correct_oep_by_range, write_msvc_oep_x64, TlsCallbackResult,
};
pub use postprocess::{
    create_data_sections, dump_process_code, install_anti_dump_fix,
    shrink_pe, DataSectionResult,
};
pub use text_tracer::{
    decide_text_trace_step, is_valid_x64_prologue_at, trace_until_real_oep, TextTraceDecision, is_oep_already_decrypted,
};
pub use trace_imports::{
    is_at_themida_vm, trace_imports, trace_is_at_api, TraceImportResult, TraceStepDecision,
    // Instruction limit per trace step (used by text decrypt walk + IAT trace).
    TRACE_LIMIT,
};
pub use version::{
    check_virtualized_oep, detect_version, is_themida_section, ThemidaVersion,
};

// ---------------------------------------------------------------------------
// Inline helpers shared across the crate
// ---------------------------------------------------------------------------

/// Compute the Theminga PE section bounds (lowest start, highest end) across
/// all sections flagged by [`version::is_themida_section`], rebased to the
/// supplied (ASLR-reloaded) image base.
///
/// This is the same computation as the private
/// `trace_imports::get_themida_section_bounds`, but exposed for callers that
/// only have the section slice (e.g. the unpacker in `cli`).  Falls back to
/// `(image_base, image_base)` when no Themida section is detected.
pub fn compute_themida_section_bounds_inline(
    pe_sections: &[mida_pe::PeSection],
    image_base: usize,
) -> (usize, usize) {
    let mut min_start = usize::MAX;
    let mut max_end = 0;
    let mut found = false;

    for section in pe_sections {
        if is_themida_section(section) {
            let start = image_base + section.virtual_address as usize;
            let end = start + section.virtual_size as usize;
            min_start = min_start.min(start);
            max_end = max_end.max(end);
            found = true;
        }
    }

    if found {
        (min_start, max_end)
    } else {
        (image_base, image_base)
    }
}
