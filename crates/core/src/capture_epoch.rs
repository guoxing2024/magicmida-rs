//! Atomic capture epoch (Route Z R0 AF1 / AF2).
//!
//! The raw-coherence invariant requires that the raw child capture `C` and the
//! authoritative slab slice `S` come from the **same stationary capture epoch**:
//! every target thread must be stopped while the live-memory bytes are read, so a
//! concurrent runtime mutation between the two reads cannot produce a spurious
//! `C != S`.
//!
//! [`CaptureEpochGuard`] is an RAII guard that freezes every target thread via the
//! backend's [`DebuggerCore::freeze_target_threads`], holds the freeze across the
//! live-memory capture window, and restores each thread to its exact pre-epoch
//! suspend count on drop (including error / early-return / panic paths).

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::debugger::DebuggerCore;
use crate::error::CoreError;

/// A thread suspended by the current capture epoch and its pre-epoch suspend
/// count (so `unfreeze` can restore the exact prior state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSuspendedThread {
    /// Target thread id.
    pub thread_id: u32,
    /// Suspend count before this epoch suspended it (0 = was running).
    pub prior_suspend_count: u32,
}

/// Epoch lifecycle state (Route Z R0 AF2 AF1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochState {
    /// Threads are frozen; `end()` / `Drop` still need to restore them.
    Active,
    /// Threads restored successfully.
    Ended,
    /// A restore attempt failed; threads may be left suspended.
    RestoreFailed,
}

/// RAII guard that freezes the target's threads for one capture epoch and
/// restores them exactly on drop.
pub struct CaptureEpochGuard<'a> {
    debugger: &'a mut dyn DebuggerCore,
    suspended: Vec<EpochSuspendedThread>,
    state: EpochState,
    /// Monotonic start of the epoch, for telemetry.
    started: Instant,
    /// Wall-clock unix ms at epoch start, for provenance.
    started_epoch_ms: u64,
}

impl<'a> CaptureEpochGuard<'a> {
    /// Begin a capture epoch: freeze every target thread. Fails closed if the
    /// backend cannot freeze the target.
    pub fn begin(debugger: &'a mut dyn DebuggerCore) -> Result<Self, CoreError> {
        let suspended = debugger
            .freeze_target_threads()?
            .into_iter()
            .map(|(tid, prior)| EpochSuspendedThread {
                thread_id: tid,
                prior_suspend_count: prior,
            })
            .collect();
        Ok(Self {
            debugger,
            suspended,
            state: EpochState::Active,
            started: Instant::now(),
            started_epoch_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        })
    }

    /// Number of target threads frozen in this epoch.
    pub fn suspended_count(&self) -> usize {
        self.suspended.len()
    }

    /// Stable snapshot of the suspended thread ids (ascending) for telemetry.
    pub fn suspended_thread_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.suspended.iter().map(|s| s.thread_id).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Epoch elapsed milliseconds since `begin`.
    pub fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    /// Wall-clock epoch start (unix ms) for provenance.
    pub fn epoch_started_ms(&self) -> u64 {
        self.started_epoch_ms
    }

    /// Current lifecycle state (used by harness/telemetry; retained for
    /// diagnostics even when not read on every production path).
    #[allow(dead_code)]
    pub fn state(&self) -> EpochState {
        self.state
    }

    /// Mutable access to the debugger while the epoch is active. Live-memory
    /// capture calls must go through this so they stay within the frozen window.
    pub fn debugger(&mut self) -> &mut dyn DebuggerCore {
        self.debugger
    }

    /// Restore every frozen thread to its exact pre-epoch suspend count and mark
    /// the epoch ended. **Idempotent**: calling again (or `Drop`) after a
    /// successful `end()` does not resume threads a second time (no
    /// suspend-count underflow). Returns an error if any resume fails, leaving
    /// the epoch in [`EpochState::RestoreFailed`].
    pub fn end(&mut self) -> Result<(), CoreError> {
        if self.state == EpochState::Active {
            let suspended: Vec<(u32, u32)> = self
                .suspended
                .iter()
                .map(|s| (s.thread_id, s.prior_suspend_count))
                .collect();
            match self.debugger.unfreeze_target_threads(&suspended) {
                Ok(()) => {
                    self.state = EpochState::Ended;
                    Ok(())
                }
                Err(e) => {
                    self.state = EpochState::RestoreFailed;
                    Err(e)
                }
            }
        } else if self.state == EpochState::RestoreFailed {
            Err(CoreError::ProcessCreation(
                "capture epoch restore already failed; not retrying".into(),
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for CaptureEpochGuard<'_> {
    fn drop(&mut self) {
        // Best-effort restore on drop; a failed restore is recorded as fatal
        // telemetry but must not panic during unwinding.
        if self.state == EpochState::Active {
            if let Err(e) = self.end() {
                eprintln!(
                    "[capture-epoch] FATAL: failed to restore {} suspended thread(s): {e:?}",
                    self.suspended.len()
                );
            }
        }
    }
}
