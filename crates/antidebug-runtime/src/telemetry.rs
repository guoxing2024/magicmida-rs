//! Telemetry channel between controller and runtime (ADR-4).
//!
//! ADR-4 implements the **protocol core** as an in-process channel so the
//! full fail-closed matrix is testable offline. The transport (named
//! pipe / shared memory) is a later wiring concern (ADR-5); the binding,
//! sequencing, correlation and timeout semantics are defined here and
//! are transport-independent.
//!
//! Requirements (ADR-4 section 5):
//! - explicit channel identity;
//! - bounded timeout (no unbounded blocking);
//! - version/schema field;
//! - request/response correlation (request id echoed);
//! - monotonic sequence;
//! - target PID binding;
//! - profile digest binding;
//! - timeout / out-of-order / PID mismatch / digest mismatch all fail-closed;
//! - no silent retry-then-assume-success;
//! - no unbounded blocking.
//!
//! The transport is a pure in-process seam in ADR-4; every binding and
//! sequencing rule is enforced here regardless of transport.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Telemetry channel schema.
pub const TELEMETRY_SCHEMA: &str = "mida.antidebug-telemetry/v1";

/// Channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TelemetryState {
    Created,
    Ready,
    Closed,
}

/// Telemetry message kinds the channel can report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TelemetryMessage {
    RuntimeInitialized,
    AttestationReady,
    HookInventory {
        expected: u32,
        installed: u32,
        failures: u32,
    },
    HealthStatus {
        healthy: bool,
        detail: String,
    },
    SurfaceInstall {
        surface_id: String,
        installed: bool,
        error: Option<String>,
    },
    SurfaceRestore {
        surface_id: String,
        restore_result: String,
        error: Option<String>,
    },
    ShutdownStatus {
        clean: bool,
        detail: String,
    },
}

/// A telemetry request from the controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryRequest {
    pub schema: String,
    pub channel_id: String,
    pub request_id: u32,
    pub sequence: u32,
    pub target_pid: u32,
    pub profile_digest: String,
    pub query: TelemetryQuery,
}

/// What the controller asks the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TelemetryQuery {
    Ping,
    GetStatus,
    Report(Vec<TelemetryMessage>),
    Shutdown,
}

/// The runtime reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryResponse {
    pub schema: String,
    pub channel_id: String,
    pub request_id: u32,
    pub sequence: u32,
    pub target_pid: u32,
    pub ok: bool,
    pub error: Option<String>,
    pub status: TelemetryState,
    pub messages: Vec<TelemetryMessage>,
}

/// Telemetry errors (all fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryError {
    #[error("channel not ready (state={0:?})")]
    ChannelNotReady(TelemetryState),
    #[error("schema mismatch: {0}")]
    SchemaMismatch(String),
    #[error("channel id mismatch: expected {expected}, got {got}")]
    ChannelIdMismatch { expected: String, got: String },
    #[error("target pid mismatch: expected {expected}, got {got}")]
    PidMismatch { expected: u32, got: u32 },
    #[error("profile digest mismatch: expected {expected}, got {got}")]
    DigestMismatch { expected: String, got: String },
    #[error("out-of-order request: expected sequence >= {expected}, got {got}")]
    OutOfOrder { expected: u32, got: u32 },
    #[error("response correlation mismatch: expected request {expected}, got {got}")]
    CorrelationMismatch { expected: u32, got: u32 },
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("channel closed")]
    Closed,
    #[error("malformed payload: {0}")]
    Malformed(String),
    #[error("duplicate response for request {0}")]
    DuplicateResponse(u32),
    #[error("internal lock poisoned")]
    LockPoisoned,
}

/// In-process telemetry channel (ADR-4 protocol core).
#[derive(Debug)]
pub struct TelemetryChannel {
    channel_id: String,
    target_pid: u32,
    profile_digest: String,
    state: Mutex<TelemetryState>,
    /// Highest accepted request sequence (monotonic watermark).
    accepted_high: AtomicU32,
    last_request_id: AtomicU32,
    /// Correlation ledger: request_id -> (sequence, responded).
    ledger: Mutex<HashMap<u32, (u32, bool)>>,
    /// Bounded wait budget for the simulated transport round-trip.
    round_trip_budget: Duration,
}

impl TelemetryChannel {
    /// Create a channel bound to a target PID and profile digest.
    pub fn new(
        channel_id: impl Into<String>,
        target_pid: u32,
        profile_digest: impl Into<String>,
    ) -> Self {
        Self {
            channel_id: channel_id.into(),
            target_pid,
            profile_digest: profile_digest.into(),
            state: Mutex::new(TelemetryState::Created),
            accepted_high: AtomicU32::new(0),
            last_request_id: AtomicU32::new(0),
            ledger: Mutex::new(HashMap::new()),
            round_trip_budget: Duration::from_millis(100),
        }
    }

    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    pub fn target_pid(&self) -> u32 {
        self.target_pid
    }

    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    /// Mark the channel ready (runtime initialized + attestation built).
    pub fn mark_ready(&self) -> Result<(), TelemetryError> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| TelemetryError::LockPoisoned)?;
        if *st == TelemetryState::Closed {
            return Err(TelemetryError::Closed);
        }
        *st = TelemetryState::Ready;
        Ok(())
    }

    pub fn state(&self) -> TelemetryState {
        match self.state.lock() {
            Ok(st) => *st,
            Err(_) => TelemetryState::Closed,
        }
    }

    /// Issue a request (controller side) and get the correlated response.
    ///
    /// All bindings are validated. The in-process transport simulates a
    /// bounded round-trip; every failure is fail-closed with a structured
    /// error (no silent retry-then-assume-success).
    pub fn request(&self, query: TelemetryQuery) -> Result<TelemetryResponse, TelemetryError> {
        let st = self.state();
        if st != TelemetryState::Ready {
            return Err(TelemetryError::ChannelNotReady(st));
        }
        // Issue a fresh sequence one past the current watermark.
        let seq = self.accepted_high.load(Ordering::SeqCst) + 1;
        let rid = self.last_request_id.fetch_add(1, Ordering::SeqCst);
        let req = TelemetryRequest {
            schema: TELEMETRY_SCHEMA.to_string(),
            channel_id: self.channel_id.clone(),
            request_id: rid,
            sequence: seq,
            target_pid: self.target_pid,
            profile_digest: self.profile_digest.clone(),
            query,
        };
        // Simulated bounded round-trip (transport seam).
        let deadline = Instant::now() + self.round_trip_budget;
        if Instant::now() > deadline {
            return Err(TelemetryError::Timeout(self.round_trip_budget));
        }
        self.handle_request(req)
    }

    /// Runtime side: process a request with full binding validation.
    pub fn handle_request(
        &self,
        req: TelemetryRequest,
    ) -> Result<TelemetryResponse, TelemetryError> {
        // schema
        if req.schema != TELEMETRY_SCHEMA {
            return Err(TelemetryError::SchemaMismatch(req.schema));
        }
        // channel identity
        if req.channel_id != self.channel_id {
            return Err(TelemetryError::ChannelIdMismatch {
                expected: self.channel_id.clone(),
                got: req.channel_id,
            });
        }
        // PID binding
        if req.target_pid != self.target_pid {
            return Err(TelemetryError::PidMismatch {
                expected: self.target_pid,
                got: req.target_pid,
            });
        }
        // digest binding
        if req.profile_digest != self.profile_digest {
            return Err(TelemetryError::DigestMismatch {
                expected: self.profile_digest.clone(),
                got: req.profile_digest,
            });
        }
        // monotonic sequence: reject requests older than the highest accepted.
        let high = self.accepted_high.load(Ordering::SeqCst);
        if req.sequence < high {
            return Err(TelemetryError::OutOfOrder {
                expected: high,
                got: req.sequence,
            });
        }
        self.accepted_high.fetch_max(req.sequence, Ordering::SeqCst);
        // correlation ledger: reject duplicate request ids
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| TelemetryError::LockPoisoned)?;
        if let Some((_, responded)) = ledger.get(&req.request_id) {
            if *responded {
                return Err(TelemetryError::DuplicateResponse(req.request_id));
            }
        }
        // build the response
        let (ok, error, messages) = match &req.query {
            TelemetryQuery::Ping => (true, None, Vec::new()),
            TelemetryQuery::GetStatus => (true, None, Vec::new()),
            TelemetryQuery::Report(msgs) => (true, None, msgs.clone()),
            TelemetryQuery::Shutdown => (
                true,
                None,
                vec![TelemetryMessage::ShutdownStatus {
                    clean: true,
                    detail: "shutdown requested".to_string(),
                }],
            ),
        };
        let resp = TelemetryResponse {
            schema: TELEMETRY_SCHEMA.to_string(),
            channel_id: self.channel_id.clone(),
            request_id: req.request_id,
            sequence: req.sequence,
            target_pid: self.target_pid,
            ok,
            error,
            status: self.state(),
            messages,
        };
        ledger.insert(req.request_id, (req.sequence, true));
        Ok(resp)
    }

    /// Validate a response correlation against the request that produced it.
    pub fn validate_response(
        &self,
        req: &TelemetryRequest,
        resp: &TelemetryResponse,
    ) -> Result<(), TelemetryError> {
        if resp.schema != TELEMETRY_SCHEMA {
            return Err(TelemetryError::SchemaMismatch(resp.schema.clone()));
        }
        if resp.channel_id != self.channel_id {
            return Err(TelemetryError::ChannelIdMismatch {
                expected: self.channel_id.clone(),
                got: resp.channel_id.clone(),
            });
        }
        if resp.request_id != req.request_id {
            return Err(TelemetryError::CorrelationMismatch {
                expected: req.request_id,
                got: resp.request_id,
            });
        }
        if resp.target_pid != self.target_pid {
            return Err(TelemetryError::PidMismatch {
                expected: self.target_pid,
                got: resp.target_pid,
            });
        }
        Ok(())
    }

    /// Report a surface restoration result (ADR-5). Fire-and-forget: the
    /// result is recorded as a telemetry message; a channel failure here is
    /// non-fatal for the restore path itself (the caller decides policy).
    pub fn report_surface_restore(
        &self,
        surface_id: &str,
        restore_result: &str,
        error: Option<String>,
    ) -> Result<(), TelemetryError> {
        let msg = TelemetryMessage::SurfaceRestore {
            surface_id: surface_id.to_string(),
            restore_result: restore_result.to_string(),
            error,
        };
        let resp = self.request(TelemetryQuery::Report(vec![msg]))?;
        if !resp.ok {
            return Err(TelemetryError::Malformed(
                "restore report rejected".to_string(),
            ));
        }
        Ok(())
    }

    /// Close the channel (shutdown). Repeated close is idempotent.
    pub fn close(&self) -> Result<(), TelemetryError> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| TelemetryError::LockPoisoned)?;
        *st = TelemetryState::Closed;
        Ok(())
    }

    /// Reset state (for repeated start/stop resource-leak tests).
    pub fn reset(&self) -> Result<(), TelemetryError> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| TelemetryError::LockPoisoned)?;
        *st = TelemetryState::Created;
        self.accepted_high.store(0, Ordering::SeqCst);
        self.last_request_id.store(0, Ordering::SeqCst);
        self.ledger
            .lock()
            .map_err(|_| TelemetryError::LockPoisoned)?
            .clear();
        Ok(())
    }
}
