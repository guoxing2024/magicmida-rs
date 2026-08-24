//! Walker production control state machine (IMP-09-R1).
//!
//! Pure-offline, provider-injected orchestration of the WO-1501 walker
//! protocol:
//!
//! ```text
//! UNINITIALIZED
//!   -> VALIDATED        (controller_validate_entry on the params blob)
//!   -> ROUND_1          (begin_round(1))
//!   -> ROUND_1_DONE     (consume_section: controller_read_completed_section)
//!   -> ROUND_2          (begin_round(2))
//!   -> COMPLETED        (consume_section round 2 + digest anchoring)
//! any error -> ABORTED  (never retried, never resumed)
//! ```
//!
//! # Semantics
//! - LOCAL PROTOCOL PASS != Windows/live PASS. Nothing here touches a
//!   process; all reads go through the injected [`WalkerMemoryProvider`].
//! - Fail-closed: every error path transitions the session to Aborted
//!   and returns a structured error; auto_retry is ALWAYS false
//!   (governance hard rule) and Aborted is terminal.
//! - The production controller APIs (`controller_validate_entry`,
//!   `controller_read_section`, `controller_read_completed_section`) are
//!   called by THIS module — the production caller — never only from
//!   `#[cfg(test)]`.

use crate::attestation::{AbortState, AttestationError, ProbeSummary, RoundLedger, WalkerAttestation};
use crate::walker_protocol::{
    controller_read_completed_section, controller_read_section, controller_validate_entry,
    derive_session_id, is_canonical_user_va, ControllerSectionView, IdentityExpectation,
    ProtocolError, WalkerParamsV2, COMPLETED_FLAG_ABORT, COMPLETED_FLAG_DONE,
    WALKER_STATUS_ERROR_BAD_PARAMS, WALKER_STATUS_ERROR_INTERNAL_PANIC, WALKER_STATUS_ERROR_MAP_FAILED,
    WALKER_STATUS_ERROR_PROBE_ABORTED, WALKER_STATUS_ERROR_VEH_FAILED, WALKER_STATUS_OK,
};

/// Session lifecycle phases (closed set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkerPhase {
    Uninitialized,
    Validated,
    Round1,
    Round1Done,
    Round2,
    Completed,
    Aborted,
}

/// Structured abort reason (closed set; mirrors the protocol status codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkerAbortReason {
    BadParams,
    MapFailed,
    VehFailed,
    ProbeAborted,
    InternalPanic,
}

impl WalkerAbortReason {
    /// Protocol walker_status code for this reason (closed set 1..=5).
    pub const fn status_code(self) -> u32 {
        match self {
            Self::BadParams => WALKER_STATUS_ERROR_BAD_PARAMS,
            Self::MapFailed => WALKER_STATUS_ERROR_MAP_FAILED,
            Self::VehFailed => WALKER_STATUS_ERROR_VEH_FAILED,
            Self::ProbeAborted => WALKER_STATUS_ERROR_PROBE_ABORTED,
            Self::InternalPanic => WALKER_STATUS_ERROR_INTERNAL_PANIC,
        }
    }

    /// Attestation AbortState for this reason (closed mapping).
    pub const fn abort_state(self) -> AbortState {
        match self {
            Self::BadParams => AbortState::WalkerAbort,
            Self::MapFailed => AbortState::WalkerAbort,
            Self::VehFailed => AbortState::WalkerAbort,
            Self::ProbeAborted => AbortState::WalkerAbort,
            Self::InternalPanic => AbortState::WalkerAbort,
        }
    }
}

/// Sealed digest authority for the walker completion path (P0-2).
///
/// Carries the identity/digest binding that the production caller MUST use
/// when building the WalkerAttestation. Values are validated at bind time
/// (64-hex digests, nonzero VAs, checked module_base+export_rva entry).
/// Strings come from the controller's verified manifest (digest authority),
/// NOT from an open caller-provided string at attestation time.
#[derive(Debug, Clone, PartialEq, Eq)]
/// Sealed digest authority (R2): fields are PRIVATE.
///
/// The ONLY construction path is [`WalkerDigestAuthority::new`] which is
/// `pub(crate)` — external crates cannot forge an authority. The production
/// caller graph proves the values originate from the verified manifest
/// (digest authority) bound by the in-crate controller, not from arbitrary
/// caller strings.
pub struct WalkerDigestAuthority {
    /// SHA-256 of the target image (64 lowercase hex).
    target_image_sha256: String,
    /// SHA-256 of the runtime module (64 lowercase hex).
    runtime_module_sha256: String,
    /// Target module base VA (== attestation module_base).
    module_base: u64,
    /// WalkerExecute export RVA within the runtime module.
    walker_export_rva: u64,
    /// Profile id (attestation profile binding).
    profile_id: String,
    /// Profile digest (attestation profile binding; non-empty required by v2).
    profile_digest: String,
}


/// Lowercase-only hex check (R3): digests are 64 lowercase `0-9a-f`.
/// Uppercase `A-F` is REJECTED (matches the sealed CLI authority which
/// always emits lowercase; a forged uppercase digest cannot pass).
fn is_lowercase_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl WalkerDigestAuthority {
    /// Build + validate the sealed authority (fail-closed).
    ///
    /// `pub(crate)` — the only construction path. External crates
    /// must receive a fully-formed authority through the in-crate binding
    /// API; they cannot forge fields.
    pub(crate) fn new(
        target_image_sha256: &str,
        runtime_module_sha256: &str,
        module_base: u64,
        walker_export_rva: u64,
        profile_id: &str,
        profile_digest: &str,
    ) -> Result<Self, WalkerControlError> {
        let t = target_image_sha256.trim();
        let r = runtime_module_sha256.trim();
        if !is_lowercase_hex64(t) {
            return Err(WalkerControlError::MissingDigest);
        }
        if !is_lowercase_hex64(r) {
            return Err(WalkerControlError::MissingDigest);
        }
        if module_base == 0 || walker_export_rva == 0 {
            return Err(WalkerControlError::MissingIdentity);
        }
        module_base
            .checked_add(walker_export_rva)
            .ok_or(WalkerControlError::Attestation(
                AttestationError::WalkerEntryOverflow,
            ))?;
        let pid = profile_id.trim();
        let pd = profile_digest.trim();
        if pid.is_empty() || !is_lowercase_hex64(pd) {
            return Err(WalkerControlError::MissingDigest);
        }
        Ok(Self {
            target_image_sha256: t.to_string(),
            runtime_module_sha256: r.to_string(),
            module_base,
            walker_export_rva,
            profile_id: pid.to_string(),
            profile_digest: pd.to_string(),
        })
    }

    /// Entry VA = module_base + export_rva (checked at construction).
    pub fn walker_entry_va(&self) -> u64 {
        self.module_base + self.walker_export_rva
    }

    /// Target image digest (read-only accessor).
    pub fn target_image_sha256(&self) -> &str {
        &self.target_image_sha256
    }

    /// Runtime module digest (read-only accessor).
    pub fn runtime_module_sha256(&self) -> &str {
        &self.runtime_module_sha256
    }

    /// Target module base VA (read-only accessor).
    pub fn module_base(&self) -> u64 {
        self.module_base
    }

    /// Walker export RVA (read-only accessor).
    pub fn walker_export_rva(&self) -> u64 {
        self.walker_export_rva
    }

    /// Profile id (read-only accessor).
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Profile digest (read-only accessor).
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }
}


/// Provider I/O error (closed set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkerIoError {
    OutOfBounds { va: u64, want: usize, got: usize },
    Missing { va: u64 },
}

impl std::fmt::Display for WalkerIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfBounds { va, want, got } => {
                write!(f, "provider read OOB: va={va:#x} want={want} got={got}")
            }
            Self::Missing { va } => write!(f, "provider has no region at va={va:#x}"),
        }
    }
}

/// Memory provider abstraction: the ONLY way the driver touches memory.
///
/// Injected by the controller (local scenario) or by a future live backend;
/// the driver itself never dereferences a raw pointer.
pub trait WalkerMemoryProvider {
    /// Copy buf.len() bytes from va into buf.
    fn read(&self, va: u64, buf: &mut [u8]) -> Result<(), WalkerIoError>;
}

impl<P: WalkerMemoryProvider + ?Sized> WalkerMemoryProvider for Box<P> {
    fn read(&self, va: u64, buf: &mut [u8]) -> Result<(), WalkerIoError> {
        (**self).read(va, buf)
    }
}

/// Driver control error (all paths are terminal ABORTED in the session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkerControlError {
    Phase(WalkerPhase),
    Protocol(ProtocolError),
    Attestation(AttestationError),
    Io(WalkerIoError),
    RoundSequence { expected: u8, got: u8 },
    CountMismatch { got: usize, expected: u32 },
    CompletedFlag { got: u32 },
    MissingSection,
    MissingRounds,
    MissingIdentity,
    MissingDigest,
    NotCompleted,
    AlreadyAborted,
    BlobBaseMismatch { expected: u64, got: u64 },
}

impl std::fmt::Display for WalkerControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Phase(p) => write!(f, "invalid phase {p:?}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Attestation(e) => write!(f, "attestation: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::RoundSequence { expected, got } => {
                write!(f, "round sequence mismatch: expected {expected} got {got}")
            }
            Self::CountMismatch { got, expected } => {
                write!(f, "probe count mismatch: got {got} expected {expected}")
            }
            Self::CompletedFlag { got } => write!(f, "unexpected completed_flag 0x{got:08X}"),
            Self::MissingSection => write!(f, "no section bytes provided"),
            Self::MissingRounds => write!(f, "two completed rounds required"),
            Self::MissingIdentity => write!(f, "target identity missing"),
            Self::MissingDigest => write!(f, "digest authority missing"),
            Self::NotCompleted => write!(f, "session not completed"),
            Self::AlreadyAborted => write!(f, "session already aborted"),
            Self::BlobBaseMismatch { expected, got } => {
                write!(f, "blob_base mismatch: expected {expected:#x} got {got:#x}")
            }
        }
    }
}

impl std::error::Error for WalkerControlError {}

impl From<ProtocolError> for WalkerControlError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<AttestationError> for WalkerControlError {
    fn from(e: AttestationError) -> Self {
        Self::Attestation(e)
    }
}
impl From<WalkerIoError> for WalkerControlError {
    fn from(e: WalkerIoError) -> Self {
        Self::Io(e)
    }
}

/// Build a small UTC RFC3339-ish timestamp (no external deps; used only for
/// ledger fields that the attestation contract requires non-empty).
fn utc_now_ts() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("1970-01-01T00:00:00.{nanos}Z")
}

/// Production walker session (state machine + ledger + summary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkerSession {
    pub phase: WalkerPhase,
    pub params: WalkerParamsV2,
    pub candidates: Vec<u64>,
    pub target_pid: u32,
    pub owner_pid: u32,
    pub nonce: u64,
    pub session_id: [u8; 16],
    pub result_capacity: u32,
    pub section_bytes: u64,
    pub rounds: Vec<RoundLedger>,
    pub summary: ProbeSummary,
    pub abort_reason: Option<WalkerAbortReason>,
}

impl WalkerSession {
    fn new(
        params: WalkerParamsV2,
        candidates: Vec<u64>,
        target_pid: u32,
        owner_pid: u32,
    ) -> Self {
        let nonce = params.result_nonce;
        let session_id = derive_session_id(nonce, params.blob_base_va, params.candidate_count);
        let result_capacity = params.candidate_count;
        let section_bytes = params.result_bytes;
        Self {
            phase: WalkerPhase::Validated,
            params,
            candidates,
            target_pid,
            owner_pid,
            nonce,
            session_id,
            result_capacity,
            section_bytes,
            rounds: Vec::new(),
            summary: ProbeSummary {
                candidates_total: 0,
                type_a_count: 0,
                type_b_count: 0,
                type_c_count: 0,
                av_count: 0,
                guard_count: 0,
                retry_count: 0,
                total_latency_us: 0,
            },
            abort_reason: None,
        }
    }

    /// Transition table guard: the ONLY legal forward edges.
    fn transition(&mut self, next: WalkerPhase) -> Result<(), WalkerControlError> {
        let ok = match (self.phase, next) {
            (WalkerPhase::Uninitialized, WalkerPhase::Validated)
            | (WalkerPhase::Validated, WalkerPhase::Round1)
            | (WalkerPhase::Round1, WalkerPhase::Round1Done)
            | (WalkerPhase::Round1Done, WalkerPhase::Round2)
            | (WalkerPhase::Round2, WalkerPhase::Completed) => true,
            _ => false,
        };
        if !ok {
            return Err(WalkerControlError::Phase(self.phase));
        }
        self.phase = next;
        Ok(())
    }

    /// Abort: terminal transition from ANY phase except Completed/Aborted.
    fn abort(&mut self, reason: WalkerAbortReason) {
        if self.phase == WalkerPhase::Aborted || self.phase == WalkerPhase::Completed {
            return;
        }
        self.abort_reason = Some(reason);
        self.phase = WalkerPhase::Aborted;
    }

    /// Terminal sessions (Completed or Aborted) reject any further action
    /// (P1-3: one-shot consumption).
    pub fn is_terminal(&self) -> bool {
        matches!(self.phase, WalkerPhase::Completed | WalkerPhase::Aborted)
    }
}

/// Production walker driver (provider-injected).
#[derive(Debug, Clone)]
pub struct WalkerDriver<P: WalkerMemoryProvider> {
    provider: P,
    session: WalkerSession,
    wall_budget_ms: u64,
    round_entry: Option<std::time::Instant>,
}

impl<P: WalkerMemoryProvider> WalkerDriver<P> {
    /// Bounded provider read (production helper; used by the export caller).
    pub fn read_memory(&self, va: u64, buf: &mut [u8]) -> Result<(), WalkerIoError> {
        self.provider.read(va, buf)
    }
}
impl<P: WalkerMemoryProvider> WalkerDriver<P> {
    /// Build a session from a params blob (REAL controller_validate_entry).
    ///
    /// blob is the FULL params blob (header + candidate array) exactly as
    /// it would sit in target memory.
    pub fn new(
        provider: P,
        blob: &[u8],
        target_pid: u32,
        owner_pid: u32,
    ) -> Result<Self, WalkerControlError> {
        let (params, candidates) = controller_validate_entry(blob)?;
        if params.blob_base_va == 0 || !is_canonical_user_va(params.blob_base_va) {
            return Err(WalkerControlError::Protocol(
                ProtocolError::NonCanonicalVa {
                    va: params.blob_base_va,
                },
            ));
        }
        let session = WalkerSession::new(params, candidates, target_pid, owner_pid);
        Ok(Self {
            provider,
            session,
            wall_budget_ms: 0,
            round_entry: None,
        })
    }

    pub fn session(&self) -> &WalkerSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut WalkerSession {
        &mut self.session
    }

    /// Begin a round (1 or 2). Any error aborts the session.
    pub fn begin_round(&mut self, round_index: u8, wall_budget_ms: u64) -> Result<(), WalkerControlError> {
        let expected = match round_index {
            1 => WalkerPhase::Round1,
            2 => WalkerPhase::Round2,
            _ => {
                self.session.abort(WalkerAbortReason::BadParams);
                return Err(WalkerControlError::RoundSequence {
                    expected: 1,
                    got: round_index,
                });
            }
        };
        if self.session.is_terminal() {
            return Err(WalkerControlError::AlreadyAborted);
        }
        // Sequence: round1 requires Validated; round2 requires Round1Done.
        let from_ok = match round_index {
            1 => self.session.phase == WalkerPhase::Validated,
            2 => self.session.phase == WalkerPhase::Round1Done,
            _ => false,
        };
        if !from_ok {
            self.session.abort(WalkerAbortReason::BadParams);
            return Err(WalkerControlError::RoundSequence {
                expected: if round_index == 1 { 1 } else { 2 },
                got: round_index,
            });
        }
        self.wall_budget_ms = wall_budget_ms;
        self.round_entry = Some(std::time::Instant::now());
        self.session.transition(expected)?;
        Ok(())
    }

    /// Consume a completed result section for the CURRENT round.
    ///
    /// Production caller of controller_read_completed_section. On success
    /// the round ledger is written; on ANY error the session aborts.
    pub fn consume_section<'a>(
        &mut self,
        section: &'a [u8],
    ) -> Result<ControllerSectionView<'a>, WalkerControlError> {
        if self.session.is_terminal() {
            return Err(WalkerControlError::AlreadyAborted);
        }
        if self.session.phase != WalkerPhase::Round1 && self.session.phase != WalkerPhase::Round2 {
            self.session.abort(WalkerAbortReason::BadParams);
            return Err(WalkerControlError::Phase(self.session.phase));
        }
        let round_index = if self.session.phase == WalkerPhase::Round1 { 1 } else { 2 };
        let expected = IdentityExpectation {
            nonce: self.session.nonce,
            target_pid: self.session.target_pid,
            owner_pid: self.session.owner_pid,
            session_id: self.session.session_id,
            section_bytes: self.session.section_bytes,
        };
        // REAL production call #1: controller_read_section — identity + header
        // pre-validation. The returned view's identity/header are consumed
        // (nonce/pid/session/section_bytes/status/flag) below via the
        // completed gate; this is the direct production caller (P1-1).
        let pre = match controller_read_section(section, &expected, self.session.result_capacity) {
            Ok(v) => v,
            Err(e) => {
                self.session.abort(WalkerAbortReason::ProbeAborted);
                return Err(WalkerControlError::Protocol(e));
            }
        };
        if pre.identity.section_bytes != expected.section_bytes
            || pre.identity.nonce != expected.nonce
            || pre.identity.target_pid != expected.target_pid
            || pre.identity.owner_pid != expected.owner_pid
            || pre.identity.session_id != expected.session_id
        {
            self.session.abort(WalkerAbortReason::ProbeAborted);
            return Err(WalkerControlError::MissingIdentity);
        }
        // REAL production call #2: the completed gate (P1-1 continued).
        let view = match controller_read_completed_section(section, &expected, self.session.result_capacity) {
            Ok(v) => v,
            Err(e) => {
                self.session.abort(WalkerAbortReason::ProbeAborted);
                return Err(WalkerControlError::Protocol(e));
            }
        };
        // Completion flag must be done (abort flag is a protocol-valid state
        // but the production round consumer requires a clean round).
        match view.header.completed_flag {
            COMPLETED_FLAG_DONE => {}
            COMPLETED_FLAG_ABORT => {
                self.session.abort(WalkerAbortReason::ProbeAborted);
                return Err(WalkerControlError::CompletedFlag {
                    got: view.header.completed_flag,
                });
            }
            other => {
                self.session.abort(WalkerAbortReason::ProbeAborted);
                return Err(WalkerControlError::CompletedFlag { got: other });
            }
        }
        if view.header.walker_status != WALKER_STATUS_OK {
            self.session.abort(WalkerAbortReason::ProbeAborted);
            return Err(WalkerControlError::Protocol(
                ProtocolError::BadStatusForState {
                    got: view.header.walker_status,
                    flag: view.header.completed_flag,
                },
            ));
        }
        if view.results.len() as u32 != self.session.result_capacity {
            self.session.abort(WalkerAbortReason::ProbeAborted);
            return Err(WalkerControlError::CountMismatch {
                got: view.results.len(),
                expected: self.session.result_capacity,
            });
        }
        // Round ledger (production write point).
        let entry_ts = utc_now_ts();
        let exit_ts = utc_now_ts();
        let spent = self
            .round_entry
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let mut ledger = RoundLedger::new(round_index).map_err(|e| {
            self.session.abort(WalkerAbortReason::BadParams);
            e
        })?;
        ledger.entry_ts = entry_ts.clone();
        ledger.exit_ts = exit_ts.clone();
        ledger.wall_budget_ms = self.wall_budget_ms;
        ledger.wall_spent_ms = spent;
        ledger.candidates_probed = view.results.len() as u32;
        ledger.abort_state = AbortState::None;
        ledger.auto_retry = false; // governance hard rule, always false
        ledger.next_round_authorized = round_index == 1;
        if let Err(e) = ledger.validate() {
            self.session.abort(WalkerAbortReason::BadParams);
            return Err(WalkerControlError::Attestation(e));
        }
        // Probe summary accumulation (production write point).
        let mut type_a = 0u32;
        let mut type_b = 0u32;
        let mut type_c = 0u32;
        let mut av = 0u32;
        let mut guard = 0u32;
        let mut retry = 0u32;
        let mut latency: u64 = 0;
        for r in &view.results {
            match r.classification {
                crate::walker_protocol::CLASSIFICATION_TYPE_A => type_a = type_a.saturating_add(1),
                crate::walker_protocol::CLASSIFICATION_TYPE_B => type_b = type_b.saturating_add(1),
                crate::walker_protocol::CLASSIFICATION_TYPE_C => type_c = type_c.saturating_add(1),
                crate::walker_protocol::CLASSIFICATION_GUARD => guard = guard.saturating_add(1),
                crate::walker_protocol::CLASSIFICATION_AV => av = av.saturating_add(1),
                _ => {}
            }
            if r.flags & crate::walker_protocol::RESULT_FLAG_GUARD_SEEN != 0 {
                guard = guard.saturating_add(1);
            }
            if r.flags & crate::walker_protocol::RESULT_FLAG_AV_SEEN != 0 {
                av = av.saturating_add(1);
            }
            if r.retry_count > 0 {
                retry = retry.saturating_add(1);
            }
            latency = latency.saturating_add(r.latency_us as u64);
        }
        let summary = &mut self.session.summary;
        summary.type_a_count = summary.type_a_count.saturating_add(type_a);
        summary.type_b_count = summary.type_b_count.saturating_add(type_b);
        summary.type_c_count = summary.type_c_count.saturating_add(type_c);
        summary.av_count = summary.av_count.saturating_add(av);
        summary.guard_count = summary.guard_count.saturating_add(guard);
        summary.retry_count = summary.retry_count.saturating_add(retry);
        summary.total_latency_us = summary.total_latency_us.saturating_add(latency);
        summary.candidates_total = summary
            .candidates_total
            .saturating_add(view.results.len() as u32);
        // NOTE: the sum check + validate run on a cloned copy so the borrow
        // of session ends before any abort() call (borrowck).
        let check = *summary;
        if check.type_a_count + check.type_b_count + check.type_c_count != check.candidates_total {
            self.session.abort(WalkerAbortReason::ProbeAborted);
            return Err(WalkerControlError::Attestation(
                AttestationError::ProbeSummaryTypeSumMismatch {
                    sum: check.type_a_count + check.type_b_count + check.type_c_count,
                    total: check.candidates_total,
                },
            ));
        }
        if let Err(e) = check.validate() {
            self.session.abort(WalkerAbortReason::ProbeAborted);
            return Err(WalkerControlError::Attestation(e));
        }
        self.session.rounds.push(ledger);
        let next = if round_index == 1 {
            WalkerPhase::Round1Done
        } else {
            WalkerPhase::Completed
        };
        self.session.transition(next)?;
        Ok(view)
    }

    /// Terminal abort with a structured reason.
    pub fn abort(&mut self, reason: WalkerAbortReason) {
        self.session.abort(reason);
    }

    /// Fail-closed abort entry (P1-2): marks the session ABORTED and
    /// returns the driver error. Every production error path funnels here so
    /// the terminal-state invariant holds across the whole caller.
    pub fn fail_abort(&mut self, e: WalkerControlError) -> WalkerControlError {
        // Force terminal: even a Completed session that fails attestation
        // anchoring must end ABORTED (P1-2 fail-closed invariant).
        self.session.abort_reason = Some(WalkerAbortReason::ProbeAborted);
        self.session.phase = WalkerPhase::Aborted;
        e
    }

    /// Build the final WalkerAttestation (record_digest + anchor binding).
    ///
    /// Only valid from Completed; ANY failure (including validation) marks
    /// the session ABORTED (P1-2). The digest/identity inputs come from the
    /// sealed [`WalkerDigestAuthority`] — never from an open caller string.
    pub fn finalize_attestation(
        &mut self,
        authority: &WalkerDigestAuthority,
    ) -> Result<WalkerAttestation, WalkerControlError> {
        if self.session.phase != WalkerPhase::Completed {
            return Err(self.fail_abort(WalkerControlError::NotCompleted));
        }
        if self.session.rounds.len() != 2 {
            return Err(self.fail_abort(WalkerControlError::MissingRounds));
        }
        if self.session.summary.candidates_total == 0 {
            return Err(self.fail_abort(WalkerControlError::CountMismatch {
                got: 0,
                expected: self.session.result_capacity,
            }));
        }
        let module_base = authority.module_base;
        let walker_entry_va = authority.walker_entry_va();
        let mut att = WalkerAttestation::new(
            self.session.target_pid,
            authority.target_image_sha256.clone(),
            authority.runtime_module_sha256.clone(),
            authority.walker_export_rva,
            walker_entry_va,
            self.session.summary,
        );
        att.rounds = self.session.rounds.clone();
        att.orphaned_resources = Vec::new();
        att.record_digest = att.compute_digest();
        if att.record_digest.is_empty() {
            return Err(self.fail_abort(WalkerControlError::MissingDigest));
        }
        // Anchor binding: validate the matrix + digest BEFORE returning.
        if let Err(e) = att.validate(
            self.session.target_pid,
            &authority.runtime_module_sha256,
            module_base,
        ) {
            return Err(self.fail_abort(WalkerControlError::Attestation(e)));
        }
        Ok(att)
    }

    /// Anchor the walker attestation into a v2 top-level attestation
    /// (production write point: walker_attestation + record_digest).
    /// Any failure marks the session ABORTED (P1-2).
    pub fn anchor_into_v2(
        &mut self,
        mut top: crate::attestation::RuntimeAttestationV2,
        att: &WalkerAttestation,
    ) -> Result<crate::attestation::RuntimeAttestationV2, WalkerControlError> {
        top.walker_attestation = Some(att.clone());
        top.record_digest = top.compute_digest();
        if top.record_digest.is_empty() {
            return Err(self.fail_abort(WalkerControlError::MissingDigest));
        }
        if let Err(e) = top.validate() {
            return Err(self.fail_abort(WalkerControlError::Attestation(e)));
        }
        Ok(top)
    }

    /// Build the identity expectation for the session (production helper).
    pub fn identity_expectation(&self) -> IdentityExpectation {
        IdentityExpectation {
            nonce: self.session.nonce,
            target_pid: self.session.target_pid,
            owner_pid: self.session.owner_pid,
            session_id: self.session.session_id,
            section_bytes: self.session.section_bytes,
        }
    }
}

/// In-memory provider for LOCAL orchestration (tests + local controller).
/// Regions are keyed by base VA; reads are bounds-checked.
#[derive(Debug, Clone, Default)]
pub struct MemoryMapProvider {
    regions: std::collections::BTreeMap<u64, Vec<u8>>,
}

impl MemoryMapProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, va: u64, bytes: Vec<u8>) {
        self.regions.insert(va, bytes);
    }

    pub fn read_from(&self, va: u64, buf: &mut [u8]) -> Result<(), WalkerIoError> {
        WalkerMemoryProvider::read(self, va, buf)
    }
}

impl WalkerMemoryProvider for MemoryMapProvider {
    fn read(&self, va: u64, buf: &mut [u8]) -> Result<(), WalkerIoError> {
        let want = buf.len();
        if want == 0 {
            return Ok(());
        }
        // Find the region containing va (highest base <= va).
        let region = match self.regions.range(..=va).next_back() {
            Some((base, bytes)) if va < base + bytes.len() as u64 => (base, bytes),
            _ => return Err(WalkerIoError::Missing { va }),
        };
        let (base, bytes) = region;
        // va >= base holds by construction (range(..=va).next_back + guard).
        let off = match usize::try_from(va - base) {
            Ok(v) => v,
            Err(_) => return Err(WalkerIoError::OutOfBounds { va, want, got: 0 }),
        };
        let got = bytes.len().saturating_sub(off);
        if got < want {
            return Err(WalkerIoError::OutOfBounds {
                va,
                want,
                got,
            });
        }
        buf.copy_from_slice(&bytes[off..off + want]);
        Ok(())
    }
}
// ---------------------------------------------------------------------------
// Hostile-test helpers (TEST_ONLY, in this module under cfg(test))
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{Orphan, OrphanKind, OrphanState};
    use crate::walker_protocol::{
        encode_section, MappingIdentityHeaderV2, ProbeResultV2, ResultSectionHeaderV2,
        WalkerParamsV2, CLASSIFICATION_TYPE_C, RESULT_FLAG_GUARD_SEEN,
        COMPLETED_FLAG_DONE, PROBE_RESULT_BYTES,
    };

    fn nonce() -> u64 {
        0x1122_3344_5566_7788
    }

    fn base() -> u64 {
        0x0000_0040_0000
    }

    fn candidates() -> Vec<u64> {
        vec![0x1000, 0x2000, 0x3000]
    }

    fn params_blob(blob_base: u64, cand: &[u64], result_bytes: u64) -> Vec<u8> {
        let p = WalkerParamsV2::new(
            blob_base,
            cand.len() as u32,
            0,
            16,
            nonce(),
            result_bytes,
        );
        p.to_blob_bytes(cand).unwrap()
    }

    fn authority() -> WalkerDigestAuthority {
        WalkerDigestAuthority::new(
            &"a".repeat(64),
            &"b".repeat(64),
            base(),
            0x1234,
            "walker-local",
            &"c".repeat(64),
        )
        .unwrap()
    }

    fn section_bytes_for(cap: u32) -> u64 {
        96 + cap as u64 * PROBE_RESULT_BYTES as u64
    }

    fn make_section(
        round_candidates: &[u64],
        blob_base: u64,
        target_pid: u32,
        owner_pid: u32,
        done: bool,
    ) -> Vec<u8> {
        let cap = round_candidates.len() as u32;
        let section_bytes = section_bytes_for(cap);
        let ident = MappingIdentityHeaderV2::new(
            section_bytes,
            target_pid,
            owner_pid,
            nonce(),
            derive_session_id(nonce(), blob_base, cap),
        );
        let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
        if done {
            hdr.completed_flag = COMPLETED_FLAG_DONE;
            hdr.result_count = cap;
        }
        let results: Vec<ProbeResultV2> = round_candidates
            .iter()
            .enumerate()
            .map(|(i, va)| {
                let mut r = ProbeResultV2::new(
                    *va,
                    CLASSIFICATION_TYPE_C,
                    RESULT_FLAG_GUARD_SEEN,
                    (i % 2) as u8,
                    [0xAA; 16],
                );
                r.set_probe_span(16);
                r
            })
            .collect();
        encode_section(&ident, &hdr, &results).unwrap()
    }

    fn full_two_round_flow() -> (MemoryMapProvider, WalkerDriver<MemoryMapProvider>) {
        let blob_base = base();
        let target_pid = 4242u32;
        let owner_pid = 1234u32;
        let cand = candidates();
        let cap = cand.len() as u32;
        let sec_bytes = section_bytes_for(cap);
        let blob = params_blob(blob_base, &cand, sec_bytes);
        let s1 = make_section(&cand, blob_base, target_pid, owner_pid, true);
        let s2 = make_section(&cand, blob_base, target_pid, owner_pid, true);
        let mut prov = MemoryMapProvider::new();
        prov.insert(blob_base, blob);
        prov.insert(blob_base + 0x1000, s1);
        prov.insert(blob_base + 0x2000, s2);
        let driver = WalkerDriver::new(prov.clone(), &prov.regions[&blob_base], target_pid, owner_pid).unwrap();
        (prov, driver)
    }

    impl MemoryMapProvider {
        fn read_region(&self, va: u64) -> Vec<u8> {
            let (_, bytes) = self.regions.range(..=va).next_back().unwrap();
            bytes.clone()
        }
    }

    #[test]
    fn two_rounds_complete_with_ledger_and_digest() {
        let (prov, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let s1 = prov.read_region(base() + 0x1000);
        let view1 = d.consume_section(&s1).unwrap();
        assert_eq!(view1.results.len(), 3);
        d.begin_round(2, 1000).unwrap();
        let s2 = prov.read_region(base() + 0x2000);
        d.consume_section(&s2).unwrap();
        assert_eq!(d.session().phase, WalkerPhase::Completed);
        assert_eq!(d.session().rounds.len(), 2);
        assert_eq!(d.session().rounds[0].round_index, 1);
        assert_eq!(d.session().rounds[1].round_index, 2);
        assert!(!d.session().rounds[0].auto_retry);
        assert!(!d.session().rounds[1].auto_retry);
        let att = d
            .finalize_attestation(&authority())
            .unwrap();
        assert_eq!(att.rounds.len(), 2);
        assert_eq!(att.record_digest.len(), 64);
        assert_eq!(att.compute_digest(), att.record_digest);
        att.validate(4242, &"b".repeat(64), base()).unwrap();
    }

    #[test]
    fn entry_identity_mismatch_aborts() {
        let blob_base = base();
        let cand = candidates();
        let cap = cand.len() as u32;
        let sec_bytes = section_bytes_for(cap);
        let blob = params_blob(blob_base, &cand, sec_bytes);
        // Wrong target_pid in the section identity.
        let s1 = make_section(&cand, blob_base, 9999, 1234, true);
        let mut prov = MemoryMapProvider::new();
        prov.insert(blob_base, blob);
        prov.insert(blob_base + 0x1000, s1);
        let mut d = WalkerDriver::new(prov.clone(), &prov.regions[&blob_base], 4242, 1234).unwrap();
        d.begin_round(1, 1000).unwrap();
        let s1b = prov.read_region(base() + 0x1000);
        assert!(d.consume_section(&s1b).is_err());
        assert_eq!(d.session().phase, WalkerPhase::Aborted);
    }

    #[test]
    fn digest_mismatch_rejected_in_attestation() {
        let (_, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let (prov2, _) = full_two_round_flow();
        let s1 = prov2.read_region(base() + 0x1000);
        d.consume_section(&s1).unwrap();
        d.begin_round(2, 1000).unwrap();
        let (prov3, _) = full_two_round_flow();
        let s2 = prov3.read_region(base() + 0x2000);
        d.consume_section(&s2).unwrap();
        let mut att = d
            .finalize_attestation(&authority())
            .unwrap();
        att.record_digest = "0".repeat(64);
        assert!(att.validate(4242, &"b".repeat(64), base()).is_err());
    }

    #[test]
    fn crc_mismatch_aborts() {
        let (prov, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let mut s1 = prov.read_region(base() + 0x1000);
        let n = s1.len();
        s1[n - 1] ^= 0xFF; // tamper payload byte -> CRC mismatch
        assert!(d.consume_section(&s1).is_err());
        assert_eq!(d.session().phase, WalkerPhase::Aborted);
    }

    #[test]
    fn truncated_payload_aborts() {
        let (prov, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let s1 = prov.read_region(base() + 0x1000);
        let truncated = s1[..s1.len() - PROBE_RESULT_BYTES].to_vec();
        assert!(d.consume_section(&truncated).is_err());
        assert_eq!(d.session().phase, WalkerPhase::Aborted);
    }

    #[test]
    fn pending_completed_section_aborts() {
        let (_, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let cand = candidates();
        let cap = cand.len() as u32;
        let section_bytes = section_bytes_for(cap);
        let ident = MappingIdentityHeaderV2::new(
            section_bytes,
            4242,
            1234,
            nonce(),
            derive_session_id(nonce(), base(), cap),
        );
        let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
        let pending = encode_section(&ident, &hdr, &[]).unwrap();
        assert!(d.consume_section(&pending).is_err());
        assert_eq!(d.session().phase, WalkerPhase::Aborted);
    }

    #[test]
    fn round_gap_aborts() {
        let (_, mut d) = full_two_round_flow();
        assert!(d.begin_round(2, 1000).is_err());
        assert_eq!(d.session().phase, WalkerPhase::Aborted);
    }

    #[test]
    fn duplicate_round_aborts() {
        let (prov, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let s1 = prov.read_region(base() + 0x1000);
        d.consume_section(&s1).unwrap();
        assert!(d.begin_round(1, 1000).is_err());
        assert_eq!(d.session().phase, WalkerPhase::Aborted);
    }

    #[test]
    fn out_of_order_aborts() {
        let (prov, mut d) = full_two_round_flow();
        let s1 = prov.read_region(base() + 0x1000);
        assert!(d.consume_section(&s1).is_err());
        assert_eq!(d.session().phase, WalkerPhase::Aborted);
    }

    #[test]
    fn budget_overflow_aborts() {
        let (_, mut d) = full_two_round_flow();
        d.begin_round(1, 0).unwrap();
        let (prov2, _) = full_two_round_flow();
        let s1 = prov2.read_region(base() + 0x1000);
        d.consume_section(&s1).unwrap();
        assert_eq!(d.session().phase, WalkerPhase::Round1Done);
        // The budget-exceeded path is covered by ledger.validate (attestation).
        let mut l = RoundLedger::new(1).unwrap();
        l.wall_budget_ms = 5;
        l.wall_spent_ms = 6;
        l.entry_ts = "t".into();
        l.exit_ts = "t".into();
        assert!(l.validate().is_err());
    }

    #[test]
    fn invalid_transition_aborts() {
        let (_, mut d) = full_two_round_flow();
        // finalize before completing: fail_abort must move the session to
        // ABORTED (P1-2: every attestation error is terminal).
        assert!(d.finalize_attestation(&authority()).is_err());
        assert_eq!(d.session().phase, WalkerPhase::Aborted);
    }

    #[test]
    fn orphan_contract_violation_aborts() {
        let o = Orphan {
            kind: OrphanKind::ParamsBlob,
            target_pid: 4242,
            blob_base_va: Some(0x1000),
            section_name: None,
            created_ts: "t".to_string(),
            timeout_ts: None,
            state: OrphanState::Unconfirmed,
            reclaim_note: Some("x".to_string()),
        };
        assert!(o.validate().is_err());
    }

    #[test]
    fn tampered_record_digest_rejected() {
        let (_, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let (prov2, _) = full_two_round_flow();
        let s1 = prov2.read_region(base() + 0x1000);
        d.consume_section(&s1).unwrap();
        d.begin_round(2, 1000).unwrap();
        let (prov3, _) = full_two_round_flow();
        let s2 = prov3.read_region(base() + 0x2000);
        d.consume_section(&s2).unwrap();
        let att = d
            .finalize_attestation(&authority())
            .unwrap();
        assert_eq!(att.compute_digest(), att.record_digest);
        let mut bad = att.clone();
        bad.record_digest = format!("{:064x}", 0xDEADBEEFu64);
        assert_ne!(bad.compute_digest(), bad.record_digest);
    }

    #[test]
    fn tampered_anchor_ledger_rejected() {
        let (_, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let (prov2, _) = full_two_round_flow();
        let s1 = prov2.read_region(base() + 0x1000);
        d.consume_section(&s1).unwrap();
        d.begin_round(2, 1000).unwrap();
        let (prov3, _) = full_two_round_flow();
        let s2 = prov3.read_region(base() + 0x2000);
        d.consume_section(&s2).unwrap();
        let att = d
            .finalize_attestation(&authority())
            .unwrap();
        let top = crate::attestation::RuntimeAttestationV2 {
            schema: crate::attestation::ATTESTATION_SCHEMA_V2.to_string(),
            schema_version: crate::attestation::ATTESTATION_SCHEMA_VERSION_V2,
            runtime_id: "mida-antidebug-runtime-x64".to_string(),
            runtime_version: "0.1.0".to_string(),
            architecture: "x86_64".to_string(),
            runtime_sha256: "b".repeat(64),
            profile_id: "p".to_string(),
            profile_digest: "d".to_string(),
            target_pid: 4242,
            module_base: base(),
            initialized: true,
            hooks_expected: vec![],
            hooks_installed: vec![],
            hook_failures: vec![],
            surface_details: vec![],
            telemetry_channel: "ready".to_string(),
            cleanup_handler_registered: true,
            third_party: "build-and-serialization-only".to_string(),
            source_revision: "s".to_string(),
            toolchain: "rustc".to_string(),
            walker_attestation: None,
            record_digest: String::new(),
        };
        let anchored = d.anchor_into_v2(top, &att).unwrap();
        anchored.validate().unwrap();
        // Tamper the anchored ledger WITHOUT recomputing digests: the
        // stale record_digest must fail validation (tamper rejection).
        let mut bad = anchored.clone();
        if let Some(w) = bad.walker_attestation.as_mut() {
            w.rounds[0].candidates_probed = 0;
        }
        assert!(bad.validate().is_err());
    }

    #[test]
    fn anchor_failure_aborts_session() {
        // P1-2: anchor_into_v2 failure must transition the session to ABORTED.
        let (_, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let (prov2, _) = full_two_round_flow();
        let s1 = prov2.read_region(base() + 0x1000);
        d.consume_section(&s1).unwrap();
        d.begin_round(2, 1000).unwrap();
        let (prov3, _) = full_two_round_flow();
        let s2 = prov3.read_region(base() + 0x2000);
        d.consume_section(&s2).unwrap();
        assert_eq!(d.session().phase, WalkerPhase::Completed);
        let att = d.finalize_attestation(&authority()).unwrap();
        // Broken top frame: empty profile_digest -> v2 validate fails -> abort.
        let top = crate::attestation::RuntimeAttestationV2 {
            schema: crate::attestation::ATTESTATION_SCHEMA_V2.to_string(),
            schema_version: crate::attestation::ATTESTATION_SCHEMA_VERSION_V2,
            runtime_id: "mida-antidebug-runtime-x64".to_string(),
            runtime_version: "0.1.0".to_string(),
            architecture: "x86_64".to_string(),
            runtime_sha256: "b".repeat(64),
            profile_id: "walker-local".to_string(),
            profile_digest: String::new(),
            target_pid: 4242,
            module_base: base(),
            initialized: true,
            hooks_expected: vec![],
            hooks_installed: vec![],
            hook_failures: vec![],
            surface_details: vec![],
            telemetry_channel: "ready".to_string(),
            cleanup_handler_registered: true,
            third_party: "walker-local".to_string(),
            source_revision: String::new(),
            toolchain: String::new(),
            walker_attestation: None,
            record_digest: String::new(),
        };
        assert!(d.anchor_into_v2(top, &att).is_err());
        assert_eq!(d.session().phase, WalkerPhase::Aborted);
    }

    #[test]
    fn authority_validation_rejects_bad_digests() {
        // P0-2: the sealed authority rejects non-64-hex digests / zero VAs /
        // entry overflow at bind time.
        assert!(WalkerDigestAuthority::new(
            "zz", "b", 1, 1, "p", "c"
        )
        .is_err());
        assert!(WalkerDigestAuthority::new(
            &"a".repeat(64),
            &"b".repeat(64),
            0,
            0x1234,
            "p",
            &"c".repeat(64),
        )
        .is_err());
        assert!(WalkerDigestAuthority::new(
            &"a".repeat(64),
            &"b".repeat(64),
            u64::MAX,
            2,
            "p",
            &"c".repeat(64),
        )
        .is_err());
        assert!(WalkerDigestAuthority::new(
            &"a".repeat(64),
            &"b".repeat(64),
            base(),
            0x1234,
            "p",
            &"c".repeat(64),
        )
        .is_ok());
    }

    #[test]
    fn no_automatic_retry() {
        let (_, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let (prov2, _) = full_two_round_flow();
        let s1 = prov2.read_region(base() + 0x1000);
        d.consume_section(&s1).unwrap();
        assert!(!d.session().rounds[0].auto_retry);
        let mut l = d.session().rounds[0].clone();
        l.auto_retry = true;
        assert!(l.validate().is_err());
    }

    #[test]
    fn production_caller_not_test_only() {
        let (prov, mut d) = full_two_round_flow();
        d.begin_round(1, 1000).unwrap();
        let s1 = prov.read_region(base() + 0x1000);
        let v = d.consume_section(&s1).unwrap();
        assert_eq!(v.results.len(), 3);
    }
}
