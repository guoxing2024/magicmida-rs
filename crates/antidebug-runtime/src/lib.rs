//! MIDA AntiDebug Compatibility Runtime - x64 runtime foundation (ADR-4).
//!
//! This crate is the **target-side runtime foundation**: the C ABI
//! surface ([`exports`]), the attestation record ([`attestation`]), the
//! telemetry channel ([`telemetry`]), and the artifact provenance
//! ([`provenance`]).
//!
//! ## Scope (ADR-4)
//!
//! - Windows **x64 only** (`x86_64-pc-windows-msvc`). x86, ARM, kernel
//!   driver and hypervisor (L6) are explicitly rejected / not built.
//! - **No anti-debug hook surface yet** (ADR-5+). The runtime honestly
//!   reports `hooks_installed = []` and an explicit unsupported status
//!   for every required surface, which correctly produces
//!   `AntiDebugRuntimePartialHooks` in the controller - a fail-closed
//!   result, not a bug.
//! - No ScyllaHide code, hook table, config, or binary. No third-party
//!   runtime DLL. `third_party = none` in provenance.
//!
//! ## Build targets
//!
//! `crate-type = ["cdylib", "rlib"]`: the same code is exported as a
//! C-ABI DLL (built to an out-of-tree target dir, never committed) and
//! as an rlib so the offline test suite exercises the identical logic
//! without loading a DLL into any process.
//!
//! ## Fail-closed contract
//!
//! The runtime only **reports** state; it never authorizes. The
//! controller decides. Attestation rules (ADR-0 evidence contract):
//!
//! - `hooks_installed != hooks_expected` -> fail-closed;
//! - `hook_failures` non-empty -> fail-closed;
//! - `initialized != true` -> fail-closed;
//! - `telemetry_channel != ready` -> fail-closed;
//! - `profile_digest` mismatch -> fail-closed;
//! - `architecture` mismatch -> fail-closed.

pub mod attestation;
pub mod exports;
pub mod provenance;
pub mod surfaces;
pub mod telemetry;

pub use attestation::{AttestationError, HookInventory, RuntimeAttestation, RuntimeStatus};
pub use exports::{
    MidaAntidebugError, MidaAntidebugGetAttestation, MidaAntidebugInitialize,
    MidaAntidebugShutdown, ATTESTATION_BUFFER_SIZE, MAX_ATTESTATION_BYTES,
};
pub use provenance::{Provenance, ProvenanceError};
pub use surfaces::{
    install_proc_002, install_proc_003, install_proc_surfaces, restore_proc_002, PebMemory,
    PebView, RestorationPolicy, RestoreResult, SurfaceError, SurfaceInstallOutcome,
    POINTER_SIZE_X64, SURFACE_AD_PROC_001, SURFACE_AD_PROC_002, SURFACE_AD_PROC_003,
};
pub use telemetry::{
    TelemetryChannel, TelemetryError, TelemetryMessage, TelemetryResponse, TelemetryState,
};
