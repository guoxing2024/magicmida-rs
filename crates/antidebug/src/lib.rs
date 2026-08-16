//! MIDA AntiDebug Compatibility Runtime - pure controller core (ADR-3A).
//!
//! This crate implements the **platform-independent controller skeleton**:
//!
//! - [`state`] - the explicit fail-closed lifecycle state machine
//!   (`ControllerState` / `ControllerEvent` / [`transition`](state::transition));
//! - [`profile`] - the per-sample profile model, validation, and the
//!   `required_candidate` to `hard_required` promotion API;
//! - [`evidence`] - the evidence event accumulator used by the state machine.
//!
//! Design constraints (ADR-3A):
//!
//! - **Pure**: no filesystem, no Windows API, no process launch, no network,
//!   no environment access, no ScyllaHide. Everything is offline-testable.
//! - **Deterministic**: `state + event` produces a `TransitionResult` via a
//!   pure function.
//! - **Fail-closed**: any failure is a terminal state; `Proceed` is only
//!   reachable from `ProbeReady` through the full success path.
//!
//! The crate deliberately does **not** implement the injector, the runtime
//! DLL, hooks, or any Windows integration - those are later ADR stages.

pub mod evidence;
pub mod profile;
pub mod state;

pub use evidence::{EvidenceEvent, EvidenceLog};
pub use profile::{
    Profile, ProfileError, ProfileRevision, PromoteError, SurfaceClass, SurfaceSpec,
};
pub use state::{transition, ControllerEvent, ControllerState, FailCode, TransitionResult};
