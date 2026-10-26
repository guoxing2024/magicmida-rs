//! # mida-run
//!
//! Drives `mida-cli.exe` as a child process and turns its log into structured
//! run state.
//!
//! # Why this crate exists, and why it is a *process* boundary
//!
//! Both the GUI (`mida-gui`) and the MCP server (`mida-mcp`) need to run the
//! unpack pipeline and know what happened.  Neither may link it directly:
//!
//! 1. The pipeline installs a global `tracing` subscriber and takes over the
//!    debug event loop.  Running it inside a GUI or an MCP server would fight
//!    with that process's own event loop, and a crash in the debugger would take
//!    the front-end down with it.
//! 2. The verified golden record (186 resolved / 9 modules / a specific
//!    SHA-256) is produced by *that exact binary*.  Keeping the process boundary
//!    means a front-end cannot silently change what the pipeline does.
//!
//! So this crate is the contract between the two sides: it spawns the CLI,
//! streams its output, and parses the log lines the CLI actually emits.  The
//! tests in [`parse`] are literal lines captured from real runs, so a change to
//! the CLI's wording breaks them here rather than silently producing a blank
//! panel or a lying status.
//!
//! # Two front-ends, one definition of success
//!
//! `mida-gui` renders [`parse::RunState`] as a phase rail and metric panel;
//! `mida-mcp` serialises the same structure as the MCP tool result.  Because
//! both read the same parser, the GUI and the MCP server can never disagree
//! about whether a run succeeded.

pub mod job;
pub mod parse;

pub use job::{find_cli, kill_tree, unpack_args, Event, Job, PackerChoice, SpawnOptions};
pub use parse::{
    Level, LogLine, Metrics, Phase, RunState, TargetKind,
};

// ---------------------------------------------------------------------------
// Convenience: a finished, self-contained run record
// ---------------------------------------------------------------------------

/// A completed run, flattened into the shape a front-end reports to a caller.
///
/// This exists so the MCP server does not have to decide *which* fields matter:
/// the same selection is used for its JSON result and could be used for a
/// future `--json` CLI flag, keeping the three front-ends consistent.
#[derive(Debug, Clone)]
pub struct RunReport {
    /// Process exit code from `mida-cli` itself (`0` = success).
    pub exit_code: i32,
    /// Whether the pipeline reported success (`Done.` and no fatal error).
    pub ok: bool,
    /// The target kind the run was classified as.
    pub kind: TargetKind,
    /// The phase the run ended in.
    pub phase: Option<Phase>,
    /// Error text when the run failed.
    pub error: Option<String>,
    /// The product path the CLI reported, if any.
    pub output_path: Option<String>,
    /// Wall-clock duration in milliseconds.
    pub elapsed_ms: u64,
    /// All extracted metrics.
    pub metrics: Metrics,
    /// The tail of the log, for diagnosis.  Full logs are large (a verbose run
    /// reaches tens of MB), so only the last [`LOG_TAIL_LINES`] are kept.
    pub log_tail: Vec<LogLine>,
}

/// How many trailing log lines a [`RunReport`] keeps.
///
/// A successful run ends in `Unpacked:` + `Done.`, and a failure ends in a
/// `[FATAL]` line with a multi-line explanation, so the tail is where the
/// evidence is.  Keeping the whole log would make an MCP tool result enormous
/// for no benefit — the CLI can always be re-run with `-v` for the full stream.
pub const LOG_TAIL_LINES: usize = 40;

impl RunReport {
    /// Build a report from the final state and the exit code.
    #[must_use]
    pub fn from_state(state: &RunState, exit_code: i32, elapsed_ms: u64) -> Self {
        let start = state.lines.len().saturating_sub(LOG_TAIL_LINES);
        Self {
            exit_code,
            // Both must agree: a `Done.` with a non-zero exit is still a failure,
            // and an exit 0 without `Done.` means the CLI died mid-pipeline
            // (e.g. the debuggee exited early and the loop broke out).
            ok: exit_code == 0 && state.finished == Some(true) && state.error.is_none(),
            kind: state.kind,
            phase: state.phase,
            error: state.error.clone(),
            output_path: state.output_path.clone(),
            elapsed_ms,
            metrics: state.metrics.clone(),
            log_tail: state.lines[start..].to_vec(),
        }
    }

    /// One-line summary for logs and MCP text content.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.ok {
            let out = self.output_path.as_deref().unwrap_or("<unknown>");
            format!(
                "OK  {}  {}  {} ms  -> {}",
                self.kind.label(),
                self.metrics.trace_label(),
                self.elapsed_ms,
                out
            )
        } else {
            let why = self
                .error
                .clone()
                .unwrap_or_else(|| format!("exit code {}", self.exit_code));
            format!("FAILED  {}  {} ms  {}", self.kind.label(), self.elapsed_ms, why)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_state() -> RunState {
        let mut s = RunState::with_kind(TargetKind::Exe);
        for line in [
            "[2026-10-24T06:36:07.533000Z] [INFO] Loading: C:\\t\\x86_c.exe",
            "[2026-10-24T06:36:07.540000Z] [INFO] Themida version: V3",
            "[2026-10-24T06:36:12.900000Z] [GOOD] Unpacked: C:\\t\\x86_cU.exe",
            "[2026-10-24T06:36:13.053000Z] [GOOD] Done.",
        ] {
            s.feed(line);
        }
        s
    }

    #[test]
    fn success_requires_both_exit_zero_and_done() {
        let r = RunReport::from_state(&ok_state(), 0, 5520);
        assert!(r.ok);
        assert_eq!(r.output_path.as_deref(), Some("C:\\t\\x86_cU.exe"));
        assert!(r.summary().starts_with("OK"));
    }

    #[test]
    fn a_done_with_nonzero_exit_is_not_success() {
        let r = RunReport::from_state(&ok_state(), 1, 10);
        assert!(!r.ok, "a non-zero exit must never be reported as success");
    }

    #[test]
    fn a_zero_exit_without_done_is_not_success() {
        // The debug loop breaks out early when the debuggee exits; the CLI then
        // returns 0 having written nothing.  That is not a success.
        let mut s = RunState::with_kind(TargetKind::Exe);
        s.feed("[2026-10-24T06:36:07.533000Z] [INFO] Loading: C:\\t\\x86_c.exe");
        let r = RunReport::from_state(&s, 0, 100);
        assert!(!r.ok);
    }

    #[test]
    fn a_fatal_error_is_never_success_even_with_exit_zero() {
        let mut s = RunState::with_kind(TargetKind::Exe);
        s.feed("[2026-10-24T06:36:07.533000Z] [FATAL] Fatal error: Dump failed: Invalid DOS signature");
        let r = RunReport::from_state(&s, 0, 100);
        assert!(!r.ok);
        assert!(r.error.is_some());
        assert!(r.summary().starts_with("FAILED"));
    }

    #[test]
    fn the_log_tail_is_bounded() {
        let mut s = RunState::with_kind(TargetKind::Exe);
        for i in 0..(LOG_TAIL_LINES * 3) {
            s.feed(&format!(
                "[2026-10-24T06:36:07.000000Z] [DEBUG] noise {i}"
            ));
        }
        let r = RunReport::from_state(&s, 0, 1);
        assert_eq!(r.log_tail.len(), LOG_TAIL_LINES);
    }
}

