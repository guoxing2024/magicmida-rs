//! Injectable cleanup policy for [`WindowsDebugger`](crate::windows_debugger::WindowsDebugger).
//!
//! The debugger's `Drop` must decide what to do with the target process.
//! The single concern is **process ownership** — did *we* create the process
//! via `CreateProcessW`?  If yes, we own its lifetime and `Drop` must kill it.
//!
//! Two ownership flavours exist, both *owned*:
//!
//! - [`ProcessOwnership::OwnedLaunch`] — `CreateProcessW` with
//!   `DEBUG_ONLY_THIS_PROCESS`.  A debug port exists from `t=0`.
//! - [`ProcessOwnership::OwnedPostAttach`] — `CreateProcessW` with
//!   `CREATE_SUSPENDED` and **no** debug port (post-attach launch mode).  We
//!   still own the process; `Drop` must `TerminateProcess` — the absence of a
//!   debug port does **not** make this a borrowed attach.
//!
//! There is **no** `BorrowedAttach` variant: a previous `DebugActiveProcess`
//! attach-from-PID constructor had no real caller in this product and was
//! removed as dead code.  If a real attach caller is added later, a borrowed
//! variant and `DebugActiveProcessStop` path can be re-introduced here.
//!
//! [`cleanup_action`] maps ownership → the action `Drop` must perform (both
//! owned variants → `TerminateAndWait`).  [`CleanupReport`] records the
//! *actual* outcome of the Win32 cleanup calls so failures (terminate
//! refused, wait timeout) are surfaced via `warn!` instead of silently
//! swallowed in a `debug!` report.
//!
//! All functions here are pure and allocation-free where possible, so the
//! decision logic can be unit-tested without launching a real target
//! (`target_process_starts = 0`).

/// How the target process came under the debugger's control.
///
/// The single source of truth for `Drop` cleanup.  Both variants are *owned*;
/// there is no borrowed variant (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOwnership {
    /// We launched the target via `CreateProcessW` with
    /// `DEBUG_ONLY_THIS_PROCESS`.  We own the process and a debug port exists
    /// from `t=0`.  `Drop` must `TerminateProcess` + bounded wait.
    OwnedLaunch,
    /// We launched the target via `CreateProcessW` with `CREATE_SUSPENDED` and
    /// **no** debug port (post-attach launch mode).  We still *own* the
    /// process, so `Drop` must `TerminateProcess` + bounded wait — the absence
    /// of a debug port does **not** make this a borrowed attach.
    OwnedPostAttach,
}

impl ProcessOwnership {
    /// `true` when the debugger created the process and therefore owns its
    /// lifetime.  Always `true` for the remaining variants (no borrowed path),
    /// but kept for call-site clarity and forward compatibility.
    #[must_use]
    pub fn is_owned(self) -> bool {
        matches!(self, Self::OwnedLaunch | Self::OwnedPostAttach)
    }
}

/// The cleanup action `Drop` must perform for a given ownership.
///
/// With the borrowed-attach dead path removed, every ownership maps to
/// [`CleanupAction::TerminateAndWait`].  The enum is retained so `Drop`'s
/// `match` stays exhaustive and a future borrowed variant can re-introduce
/// `Detach` without touching call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupAction {
    /// `TerminateProcess` followed by a bounded `WaitForSingleObject`.
    TerminateAndWait,
}

/// Decide the cleanup action for a given ownership.
///
/// Pure and side-effect free — the injectable decision point tests exercise
/// without touching the kernel.  Both owned variants map to
/// `TerminateAndWait`.
///
/// # Panics
///
/// Never.
#[must_use]
pub fn cleanup_action(ownership: ProcessOwnership) -> CleanupAction {
    match ownership {
        ProcessOwnership::OwnedLaunch | ProcessOwnership::OwnedPostAttach => {
            CleanupAction::TerminateAndWait
        }
    }
}

/// Outcome of the bounded `WaitForSingleObject` call in `Drop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The process exited within the timeout (`WAIT_OBJECT_0`).
    Signaled,
    /// The timeout elapsed before the process exited (`WAIT_TIMEOUT`).
    Timeout,
    /// `WaitForSingleObject` itself failed (e.g. invalid handle).  Carries the
    /// Win32 error code from `GetLastError`.
    Failed(u32),
}

/// Recorded outcome of the Win32 cleanup calls performed in `Drop`.
///
/// Every field is `Option` because only the subset relevant to the chosen
/// [`CleanupAction`] is populated.  This struct exists so `Drop` can emit a
/// single `warn!`/`debug!` diagnostic summarising terminate / wait results
/// instead of swallowing errors silently.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Ownership that drove the decision.
    pub ownership: Option<ProcessOwnership>,
    /// Action that was performed.
    pub action: Option<CleanupAction>,
    /// `true` when `TerminateProcess` returned success.
    pub terminate_ok: Option<bool>,
    /// Win32 error code from `GetLastError` when `TerminateProcess` failed.
    pub terminate_win32: Option<u32>,
    /// Outcome of the bounded wait (only for `TerminateAndWait`).
    pub wait: Option<WaitOutcome>,
}

impl CleanupReport {
    /// Build the report for an owned `Drop`: terminate + bounded wait.
    #[must_use]
    pub fn for_terminate(
        ownership: ProcessOwnership,
        terminate_ok: bool,
        terminate_win32: Option<u32>,
        wait: WaitOutcome,
    ) -> Self {
        Self {
            ownership: Some(ownership),
            action: Some(CleanupAction::TerminateAndWait),
            terminate_ok: Some(terminate_ok),
            terminate_win32,
            wait: Some(wait),
        }
    }

    /// Build the report for a construction-midway-failure `Drop` where the
    /// process handle exists and ownership is owned, but the cleanup calls
    /// themselves could not be attempted (e.g. the handle was already
    /// invalid).  Fail-closed: no action claimed, no success recorded.
    #[must_use]
    pub fn for_construction_failure(ownership: ProcessOwnership) -> Self {
        Self {
            ownership: Some(ownership),
            action: Some(cleanup_action(ownership)),
            terminate_ok: None,
            terminate_win32: None,
            wait: None,
        }
    }

    /// `true` when every attempted Win32 call succeeded and the wait
    /// signaled.  Used by `Drop` to choose `debug!` (success) vs `warn!`
    /// (failure/timeout).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.terminate_ok == Some(true) && matches!(self.wait, Some(WaitOutcome::Signaled) | None)
    }

    /// Human-readable one-line summary for `tracing`.
    #[must_use]
    pub fn summary(&self) -> String {
        let own = format!("{:?}", self.ownership);
        let act = match self.action {
            Some(a) => format!("{:?}", a),
            None => "None".to_string(),
        };
        let term = match (self.terminate_ok, self.terminate_win32) {
            (Some(true), _) => "ok".to_string(),
            (Some(false), Some(c)) => format!("FAILED(win32={c})"),
            (Some(false), None) => "FAILED".to_string(),
            (None, _) => "n/a".to_string(),
        };
        let wait = match self.wait {
            Some(WaitOutcome::Signaled) => "signaled".to_string(),
            Some(WaitOutcome::Timeout) => "TIMEOUT".to_string(),
            Some(WaitOutcome::Failed(c)) => format!("FAILED(win32={c})"),
            None => "n/a".to_string(),
        };
        format!("ownership={own} action={act} terminate={term} wait={wait}")
    }
}

// ---------------------------------------------------------------------------
// Tests — injectable cleanup policy (no real target process is started)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Owned launch (CreateProcessW + DEBUG_ONLY_THIS_PROCESS) → terminate +
    /// bounded wait.
    #[test]
    fn owned_launch_terminates_and_waits() {
        assert_eq!(
            cleanup_action(ProcessOwnership::OwnedLaunch),
            CleanupAction::TerminateAndWait
        );
        assert!(ProcessOwnership::OwnedLaunch.is_owned());
    }

    /// Owned post-attach launch (CreateProcessW + CREATE_SUSPENDED, no debug
    /// port) still owns the process → terminate + bounded wait.  Regression
    /// for the old `post_attach` boolean that detached an owned process.
    #[test]
    fn owned_post_attach_terminates_and_waits() {
        assert_eq!(
            cleanup_action(ProcessOwnership::OwnedPostAttach),
            CleanupAction::TerminateAndWait
        );
        assert!(ProcessOwnership::OwnedPostAttach.is_owned());
    }

    /// Happy-path report: terminate ok + wait signaled → `is_clean()` true.
    #[test]
    fn report_for_terminate_success() {
        let r = CleanupReport::for_terminate(
            ProcessOwnership::OwnedLaunch,
            true,
            None,
            WaitOutcome::Signaled,
        );
        assert_eq!(r.action, Some(CleanupAction::TerminateAndWait));
        assert_eq!(r.terminate_ok, Some(true));
        assert_eq!(r.wait, Some(WaitOutcome::Signaled));
        assert!(r.is_clean());
        assert!(r.summary().contains("terminate=ok"));
        assert!(r.summary().contains("wait=signaled"));
    }

    /// Timeout scenario: terminate succeeds but the process refuses to exit
    /// within the bounded wait → `WaitOutcome::Timeout` recorded, `is_clean()`
    /// false so `Drop` warns rather than debug-logs.
    #[test]
    fn report_for_terminate_wait_timeout() {
        let r = CleanupReport::for_terminate(
            ProcessOwnership::OwnedPostAttach,
            true,
            None,
            WaitOutcome::Timeout,
        );
        assert_eq!(r.wait, Some(WaitOutcome::Timeout));
        assert!(!r.is_clean());
        assert!(r.summary().contains("wait=TIMEOUT"));
    }

    /// Terminate itself fails (e.g. insufficient rights / recycled handle):
    /// the Win32 error is recorded, `is_clean()` false.
    #[test]
    fn report_for_terminate_failure_records_win32() {
        let r = CleanupReport::for_terminate(
            ProcessOwnership::OwnedLaunch,
            false,
            Some(5),                // ERROR_ACCESS_DENIED
            WaitOutcome::Failed(6), // ERROR_INVALID_HANDLE from the wait
        );
        assert_eq!(r.terminate_ok, Some(false));
        assert_eq!(r.terminate_win32, Some(5));
        assert_eq!(r.wait, Some(WaitOutcome::Failed(6)));
        assert!(!r.is_clean());
        assert!(r.summary().contains("terminate=FAILED(win32=5)"));
    }

    /// Construction-midway-failure: ownership is already assigned (so the
    /// intended action is known) but no Win32 call has been attempted yet.
    /// The report must NOT claim success for any call.
    #[test]
    fn report_for_construction_failure_claims_no_success() {
        let r = CleanupReport::for_construction_failure(ProcessOwnership::OwnedPostAttach);
        assert_eq!(r.ownership, Some(ProcessOwnership::OwnedPostAttach));
        assert_eq!(r.action, Some(CleanupAction::TerminateAndWait));
        assert_eq!(r.terminate_ok, None);
        assert_eq!(r.wait, None);
        assert!(!r.is_clean());
        assert!(r.summary().contains("action=TerminateAndWait"));
    }

    /// Invariant: every ownership maps to `TerminateAndWait` (no detach path).
    #[test]
    fn ownership_action_invariant() {
        for own in [
            ProcessOwnership::OwnedLaunch,
            ProcessOwnership::OwnedPostAttach,
        ] {
            assert_eq!(cleanup_action(own), CleanupAction::TerminateAndWait);
            assert!(own.is_owned());
        }
    }
}
