//! Acceptance verdicts (see `docs/ACCEPTANCE_CONTRACT.md`).

use serde::{Deserialize, Serialize};

/// Three-state acceptance verdict.
///
/// R0B must never emit [`Verdict::Accepted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Verdict {
    Rejected,
    StructuralPassBehaviorPending,
    /// Reserved for a future phase with behavioral evidence.
    /// Emitting this value in R0B is a contract violation.
    Accepted,
}

impl Verdict {
    /// Process exit code for a completed PE evaluation.
    ///
    /// - `0` — `StructuralPassBehaviorPending` **or** `Accepted` (CLI prints verdict)
    /// - `2` — rejected
    ///
    /// R0B `check-static` never emits `Accepted`. Behavioral
    /// `check-with-behavior` may emit `Accepted` with exit `0`.
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::StructuralPassBehaviorPending => 0,
            Verdict::Rejected => 2,
            Verdict::Accepted => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Rejected => "Rejected",
            Verdict::StructuralPassBehaviorPending => "StructuralPassBehaviorPending",
            Verdict::Accepted => "Accepted",
        }
    }
}
