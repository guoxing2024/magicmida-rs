//! Evidence event accumulator (ADR-3A).
//!
//! The state machine accumulates an [`EvidenceEvent`] on every transition.
//! Requirements:
//!
//! - sequence is monotonically increasing;
//! - events collected before a failure are retained (never cleared);
//! - failure events carry the `fail_code`;
//! - `Proceed` requires the full success-path event chain.

use crate::state::{ControllerEvent, ControllerState, FailCode};

/// A single evidence event produced by a transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceEvent {
    pub state: ControllerState,
    pub event: ControllerEvent,
    pub sequence: u32,
    pub evidence_ref: Option<String>,
    pub fail_code: Option<FailCode>,
}

impl EvidenceEvent {
    pub fn new(
        state: ControllerState,
        event: ControllerEvent,
        sequence: u32,
        fail_code: Option<FailCode>,
    ) -> Self {
        Self {
            state,
            event,
            sequence,
            evidence_ref: None,
            fail_code,
        }
    }

    pub fn with_ref(mut self, evidence_ref: impl Into<String>) -> Self {
        self.evidence_ref = Some(evidence_ref.into());
        self
    }
}

/// Ordered evidence log with monotonic sequence assignment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceLog {
    events: Vec<EvidenceEvent>,
    next_sequence: u32,
}

impl EvidenceLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event, assigning the next monotonic sequence number.
    pub fn push(&mut self, event: EvidenceEvent) -> u32 {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.events.push(event);
        seq
    }

    /// Extend from a transition result (which already carries sequences).
    pub fn extend(&mut self, events: impl IntoIterator<Item = EvidenceEvent>) {
        for e in events {
            if e.sequence >= self.next_sequence {
                self.next_sequence = e.sequence.wrapping_add(1);
            }
            self.events.push(e);
        }
    }

    pub fn events(&self) -> &[EvidenceEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Whether any event carries a fail code.
    pub fn has_failure(&self) -> bool {
        self.events.iter().any(|e| e.fail_code.is_some())
    }

    /// First fail code in the log, if any.
    pub fn first_fail_code(&self) -> Option<FailCode> {
        self.events.iter().find_map(|e| e.fail_code)
    }

    /// The chain of states visited (in order).
    pub fn state_chain(&self) -> Vec<ControllerState> {
        self.events.iter().map(|e| e.state).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ControllerState as S;

    #[test]
    fn sequence_is_monotonic() {
        let mut log = EvidenceLog::new();
        let e1 = log.push(EvidenceEvent::new(
            S::Unresolved,
            ControllerEvent::DependenciesVerified,
            0,
            None,
        ));
        let e2 = log.push(EvidenceEvent::new(
            S::DependencyVerified,
            ControllerEvent::ProfileValidated,
            0,
            None,
        ));
        let e3 = log.push(EvidenceEvent::new(
            S::ProfileVerified,
            ControllerEvent::TargetIdentityValidated,
            0,
            None,
        ));
        assert!(e1 < e2 && e2 < e3);
        assert_eq!(log.events().len(), 3);
    }

    #[test]
    fn failure_keeps_prior_events() {
        let mut log = EvidenceLog::new();
        log.push(EvidenceEvent::new(
            S::Unresolved,
            ControllerEvent::DependenciesVerified,
            0,
            None,
        ));
        log.push(EvidenceEvent::new(
            S::DependencyVerified,
            ControllerEvent::ProfileValidated,
            0,
            None,
        ));
        let fail = EvidenceEvent::new(
            S::ProfileMismatch,
            ControllerEvent::ProfileRejected,
            0,
            Some(FailCode::AntiDebugProfileMismatch),
        );
        log.push(fail);
        assert_eq!(log.len(), 3);
        assert!(log.has_failure());
        assert_eq!(
            log.first_fail_code(),
            Some(FailCode::AntiDebugProfileMismatch)
        );
        // prior success events retained
        assert_eq!(log.events()[0].state, S::Unresolved);
        assert_eq!(log.events()[1].state, S::DependencyVerified);
    }
}
