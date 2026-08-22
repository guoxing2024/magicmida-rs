//! Walker wire protocol v2 (WO-1501).
//!
//! Pure-offline, dependency-light binary contract for the Walker IPC:
//!
//! - WalkerParamsV2             controller -> target params blob
//!                              (self-relative offsets, no cross-process pointers)
//! - MappingIdentityHeaderV2    mapping/section identity header (nonce, PID,
//!                              session binding; controller- and target-side checks)
//! - ResultSectionHeaderV2      result section header (initial / done / abort state,
//!                              CRC coverage rules, completion visibility order)
//! - ProbeResultV2              fixed-layout per-candidate probe record
//!
//! Scope of this module (protocol layer only)
//! ==========================================
//! Everything in this file is wire-contract verification: layout constants,
//! checked encode/decode, bounds validation, canonical VA rules, page-crossing
//! rules, CRC coverage and reject tests. It runs fully offline.
//!
//! NOT verified here (explicitly out of scope): Windows behaviour —
//! CreateFileMappingW / OpenFileMappingW / MapViewOfFile / VirtualAllocEx /
//! WriteProcessMemory / CreateRemoteThread / AddVectoredExceptionHandler and
//! any live-process probing. Those are separate implementation work orders
//! and must NOT be claimed verified from this module's tests.
//!
//! Fail-closed design rules
//! ========================
//! - Every offset/count/stride computation is checked arithmetic; overflow,
//!   out-of-bounds and inconsistent totals are rejected, never truncated.
//! - Non-canonical x64 VAs, zero VAs and page-crossing probe spans are rejected.
//! - Unknown option/flag bits and unknown status/classification values are
//!   rejected (closed set).
//! - A section in COMPLETED_FLAG_PENDING state must not expose a result
//!   payload (result_count must be 0); results are only readable after
//!   done/abort completion flags.

use std::fmt;

/// Protocol version carried by every header.
pub const PROTOCOL_VERSION: u16 = 2;

/// Params blob magic: bytes "WALK" stored little-endian.
pub const PARAMS_MAGIC: u32 = u32::from_le_bytes(*b"WALK");
/// Result section header magic: bytes "WRES" stored little-endian.
pub const RESULT_MAGIC: u32 = u32::from_le_bytes(*b"WRES");
/// Mapping identity header magic: bytes "MIDA" stored little-endian.
pub const IDENTITY_MAGIC: u32 = u32::from_le_bytes(*b"MIDA");

/// Fixed params header size (== candidate array offset).
pub const PARAMS_HEADER_BYTES: usize = 0x40;
/// Candidate array offset inside the params blob (== header size).
pub const CANDIDATE_OFF: usize = 0x40;
/// Candidate stride: every candidate is one u64 target VA.
pub const CANDIDATE_STRIDE: usize = 8;
/// Params header CRC covers [0x00, 0x38) (magic..=result_bytes).
pub const PARAMS_CRC_RANGE_END: usize = 0x38;

/// Mapping identity header size.
pub const IDENTITY_HEADER_BYTES: usize = 0x38;
/// Result section header size.
pub const RESULT_HEADER_BYTES: usize = 0x28;
/// Minimum result section size (identity + result header).
pub const MIN_SECTION_HEADER_BYTES: usize = IDENTITY_HEADER_BYTES + RESULT_HEADER_BYTES;
/// Fixed per-probe result record size.
pub const PROBE_RESULT_BYTES: usize = 0x28;

/// Probe span bounds (bytes read per probe).
pub const MIN_PROBE_SPAN: u16 = 1;
/// Default probe span (WO-1301A design default).
pub const DEFAULT_PROBE_SPAN: u16 = 16;
/// Absolute maximum probe span.
pub const MAX_PROBE_SPAN: u16 = 64;

/// Maximum candidate count per walker round.
pub const MAX_CANDIDATE_COUNT: u32 = 4096;
/// Maximum params blob size (header + max candidates).
pub const MAX_BLOB_BYTES: usize =
    PARAMS_HEADER_BYTES + MAX_CANDIDATE_COUNT as usize * CANDIDATE_STRIDE;
/// Hard cap for result section bytes (identity + header + capacity * stride).
pub const MAX_RESULT_SECTION_BYTES: u64 = 1024 * 1024;

/// Result section completion state: not started / in progress (no payload
/// readable yet).
pub const COMPLETED_FLAG_PENDING: u32 = 0;
/// Normal completion: payload fully written, CRC valid.
pub const COMPLETED_FLAG_DONE: u32 = 1;
/// Abort completion: walker stopped early with a status error; payload may be
/// partial but CRC still covers whatever result_count records were written.
pub const COMPLETED_FLAG_ABORT: u32 = 0xDEAD_0001;

/// Walker status codes (mirrored into the result header and the return code).
pub const WALKER_STATUS_OK: u32 = 0;
pub const WALKER_STATUS_ERROR_BAD_PARAMS: u32 = 1;
pub const WALKER_STATUS_ERROR_MAP_FAILED: u32 = 2;
pub const WALKER_STATUS_ERROR_VEH_FAILED: u32 = 3;
pub const WALKER_STATUS_ERROR_PROBE_ABORTED: u32 = 4;
pub const WALKER_STATUS_ERROR_INTERNAL_PANIC: u32 = 5;
/// Closed set of valid walker status codes.
pub const WALKER_STATUS_MAX: u32 = 5;

/// Walker options (closed set; unknown bits rejected).
pub const OPTION_NONE: u16 = 0;
/// Abort the round on the first repeated non-guard AV instead of skipping the
/// candidate (stop-loss accelerator).
pub const OPTION_ABORT_ON_REPEATED_AV: u16 = 1 << 0;
/// Mask of all known option bits.
pub const OPTION_KNOWN_MASK: u16 = 0x0001;

/// Probe classifications (closed set).
pub const CLASSIFICATION_UNKNOWN: u32 = 0;
/// Type A: encrypted / invalid (repeated non-guard AV).
pub const CLASSIFICATION_TYPE_A: u32 = 1;
/// Type B: decrypted during probe (guard observed, retry read succeeded).
pub const CLASSIFICATION_TYPE_B: u32 = 2;
/// Type C: plaintext readable, no guard/AV observed.
pub const CLASSIFICATION_TYPE_C: u32 = 3;
/// Guard page violation observed at the probe address.
pub const CLASSIFICATION_GUARD: u32 = 4;
/// Access violation observed at the probe address.
pub const CLASSIFICATION_AV: u32 = 5;
/// Closed set of valid classifications.
pub const CLASSIFICATION_MAX: u32 = 5;

/// Per-probe result flags (closed set).
pub const RESULT_FLAG_NONE: u8 = 0;
pub const RESULT_FLAG_GUARD_SEEN: u8 = 1 << 0;
pub const RESULT_FLAG_AV_SEEN: u8 = 1 << 1;
pub const RESULT_FLAG_RETRIED: u8 = 1 << 2;
/// Mask of all known result flag bits.
pub const RESULT_FLAG_KNOWN_MASK: u8 = 0x07;

/// Size of the derived session id (16 bytes).
pub const WALKER_SESSION_ID_BYTES: usize = 16;

/// Upper bound of the x64 user-mode canonical range (48-bit sign-extended).
pub const X64_USER_CANONICAL_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;
/// Lower bound of the x64 kernel-mode canonical range.
pub const X64_KERNEL_CANONICAL_MIN: u64 = 0xFFFF_8000_0000_0000;
/// Page size used for the probe-span crossing rule.
pub const PAGE_SIZE: u64 = 0x1000;
/// Errors produced by protocol encode/decode/validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    BufferTooShort {
        need: usize,
        got: usize,
    },
    BadMagic {
        got: u32,
    },
    BadVersion {
        got: u16,
        expected: u16,
    },
    BadHeaderBytes {
        got: u16,
        expected: u16,
    },
    BadCandidateOff {
        got: u32,
        expected: u32,
    },
    BadCandidateStride {
        got: u16,
        expected: u16,
    },
    Overflow,
    CountTooLarge {
        got: u64,
        max: u64,
    },
    OutOfBounds {
        start: u64,
        end: u64,
        total: u64,
    },
    NonCanonicalVa {
        va: u64,
    },
    ZeroVa {
        va: u64,
    },
    PageCross {
        va: u64,
        span: u16,
    },
    BadProbeSpan {
        got: u16,
        min: u16,
        max: u16,
    },
    ZeroNonce,
    BadResultBytes {
        got: u64,
    },
    BadBlobTotalBytes {
        got: u64,
    },
    CrcMismatch {
        stored: u32,
        computed: u32,
    },
    UnknownOptionFlags {
        got: u16,
    },
    UnknownResultFlags {
        got: u8,
    },
    BadClassification {
        got: u32,
    },
    BadResultStride {
        got: u32,
        expected: u32,
    },
    ResultsOffTooSmall {
        got: u32,
        min: u32,
    },
    ResultsOffUnaligned {
        got: u32,
    },
    BadCompletedFlag {
        got: u32,
    },
    BadStatusForState {
        got: u32,
        flag: u32,
    },
    UnknownWalkerStatus {
        got: u32,
    },
    BadSectionBytes {
        got: u64,
    },
    IdentityMismatch {
        what: &'static str,
        expected: u64,
        got: u64,
    },
    SessionIdMismatch,
    CandidateCountMismatch {
        got: usize,
        declared: u32,
    },
    ResultCountExceedsCapacity {
        got: u32,
        capacity: u32,
    },
    InconsistentPendingCount {
        got: u32,
    },
    BadRetryCount {
        got: u8,
    },
    BadReserved {
        got: u32,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { need, got } => {
                write!(f, "buffer too short: need {need} got {got}")
            }
            Self::BadMagic { got } => write!(f, "bad magic 0x{got:08X}"),
            Self::BadVersion { got, expected } => {
                write!(f, "unsupported version {got}, expected {expected}")
            }
            Self::BadHeaderBytes { got, expected } => {
                write!(f, "header_bytes {got}, expected {expected}")
            }
            Self::BadCandidateOff { got, expected } => {
                write!(f, "candidate_off {got}, expected {expected}")
            }
            Self::BadCandidateStride { got, expected } => {
                write!(f, "candidate_stride {got}, expected {expected}")
            }
            Self::Overflow => write!(f, "integer overflow in offset arithmetic"),
            Self::CountTooLarge { got, max } => write!(f, "count {got} exceeds maximum {max}"),
            Self::OutOfBounds { start, end, total } => {
                write!(f, "region [{start:#x}, {end:#x}) out of bounds for total {total:#x}")
            }
            Self::NonCanonicalVa { va } => write!(f, "non-canonical x64 VA 0x{va:016X}"),
            Self::ZeroVa { va } => write!(f, "VA 0x{va:016X} must not be zero"),
            Self::PageCross { va, span } => write!(
                f,
                "probe span {span} crosses a 4KiB page boundary at VA 0x{va:016X}"
            ),
            Self::BadProbeSpan { got, min, max } => {
                write!(f, "probe span {got} outside allowed range [{min}, {max}]")
            }
            Self::ZeroNonce => write!(f, "nonce must not be zero"),
            Self::BadResultBytes { got } => write!(f, "result_bytes {got} inconsistent"),
            Self::BadBlobTotalBytes { got } => {
                write!(f, "blob_total_bytes {got} inconsistent with header+candidates")
            }
            Self::CrcMismatch { stored, computed } => {
                write!(f, "header crc mismatch: stored 0x{stored:08X} computed 0x{computed:08X}")
            }
            Self::UnknownOptionFlags { got } => write!(f, "unknown options flags 0x{got:04X}"),
            Self::UnknownResultFlags { got } => write!(f, "unknown result flags 0x{got:02X}"),
            Self::BadClassification { got } => write!(f, "invalid classification {got}"),
            Self::BadResultStride { got, expected } => {
                write!(f, "result_stride {got}, expected {expected}")
            }
            Self::ResultsOffTooSmall { got, min } => {
                write!(f, "results_off {got} below minimum {min}")
            }
            Self::ResultsOffUnaligned { got } => write!(f, "results_off {got} not 8-byte aligned"),
            Self::BadCompletedFlag { got } => write!(f, "invalid completed_flag 0x{got:08X}"),
            Self::BadStatusForState { got, flag } => write!(
                f,
                "walker_status {got} inconsistent with completed_flag 0x{flag:08X}"
            ),
            Self::UnknownWalkerStatus { got } => write!(f, "unknown walker_status {got}"),
            Self::BadSectionBytes { got } => write!(f, "section_bytes {got} inconsistent"),
            Self::IdentityMismatch { what, expected, got } => {
                write!(f, "identity mismatch: {what} expected 0x{expected:X} got 0x{got:X}")
            }
            Self::SessionIdMismatch => write!(f, "session id mismatch"),
            Self::CandidateCountMismatch { got, declared } => {
                write!(f, "candidate count {got} does not match declared {declared}")
            }
            Self::ResultCountExceedsCapacity { got, capacity } => {
                write!(f, "result count {got} exceeds capacity {capacity}")
            }
            Self::InconsistentPendingCount { got } => {
                write!(f, "pending section must have result_count 0, got {got}")
            }
            Self::BadRetryCount { got } => write!(f, "retry_count {got} exceeds contract maximum 1"),
            Self::BadReserved { got } => write!(f, "reserved field must be zero, got 0x{got:08X}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Standard CRC-32 (IEEE 802.3, polynomial 0xEDB88320), bitwise reference
/// implementation. Known vector: crc32(b"123456789") == 0xCBF43926.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// True when va is canonical in the x64 user-mode range and non-zero.
pub fn is_canonical_user_va(va: u64) -> bool {
    va != 0 && va <= X64_USER_CANONICAL_MAX
}

/// True when va is canonical in either x64 half (user or kernel).
pub fn is_canonical_x64(va: u64) -> bool {
    va <= X64_USER_CANONICAL_MAX || va >= X64_KERNEL_CANONICAL_MIN
}

/// True when a probe span of span bytes starting at va stays inside
/// one 4KiB page.
pub fn page_span_fits(va: u64, span: u16) -> bool {
    let off = va & (PAGE_SIZE - 1);
    (off as u128 + span as u128) <= PAGE_SIZE as u128
}

/// Derive the 16-byte session id binding a result section to a specific
/// params blob: nonce (8 LE) ++ low 4 bytes of blob_base_va ++
/// candidate_count (4 LE).
///
/// This is an identity binding (non-cryptographic derivation); collision
/// resistance comes from the CSPRNG nonce the controller generated.
pub fn derive_session_id(nonce: u64, blob_base_va: u64, candidate_count: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&nonce.to_le_bytes());
    let base = blob_base_va.to_le_bytes();
    out[8..12].copy_from_slice(&base[0..4]);
    out[12..16].copy_from_slice(&candidate_count.to_le_bytes());
    out
}

/// Controller -> target params blob header (fixed 0x40 bytes).
///
/// Layout (little-endian)
/// ----------------------
/// 0x00 magic u32 "WALK"
/// 0x04 version u16 2
/// 0x06 header_bytes u16 0x40
/// 0x08 blob_total_bytes u64 header + candidate array
/// 0x10 blob_base_va u64 self-relative anchor (target VA)
/// 0x18 candidate_off u32 0x40
/// 0x1C candidate_count u32 <= 4096
/// 0x20 candidate_stride u16 8
/// 0x22 options_flags u16 closed set
/// 0x24 probe_span u16 [1, 64]
/// 0x26 _reserved u16 0
/// 0x28 result_nonce u64 non-zero (section identity)
/// 0x30 result_bytes u64 result section size
/// 0x38 header_crc32 u32 CRC32 of [0x00, 0x38)
/// 0x3C _reserved2 u32 0
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkerParamsV2 {
    pub magic: u32,
    pub version: u16,
    pub header_bytes: u16,
    pub blob_total_bytes: u64,
    pub blob_base_va: u64,
    pub candidate_off: u32,
    pub candidate_count: u32,
    pub candidate_stride: u16,
    pub options_flags: u16,
    pub probe_span: u16,
    pub _reserved: u16,
    pub result_nonce: u64,
    pub result_bytes: u64,
    pub header_crc32: u32,
    pub _reserved2: u32,
}

impl WalkerParamsV2 {
    /// Fixed params header size.
    pub const BYTES: usize = PARAMS_HEADER_BYTES;

    /// Create a params header. header_crc32 is computed at to_blob_bytes
    /// time; the value stored here is overwritten by the encoder.
    pub fn new(
        blob_base_va: u64,
        candidate_count: u32,
        options_flags: u16,
        probe_span: u16,
        result_nonce: u64,
        result_bytes: u64,
    ) -> Self {
        Self {
            magic: PARAMS_MAGIC,
            version: PROTOCOL_VERSION,
            header_bytes: PARAMS_HEADER_BYTES as u16,
            blob_total_bytes: 0, // filled by to_blob_bytes
            blob_base_va,
            candidate_off: CANDIDATE_OFF as u32,
            candidate_count,
            candidate_stride: CANDIDATE_STRIDE as u16,
            options_flags,
            probe_span,
            _reserved: 0,
            result_nonce,
            result_bytes,
            header_crc32: 0,
            _reserved2: 0,
        }
    }

    /// Encode header + candidate array into one self-contained blob.
    pub fn to_blob_bytes(&self, candidates: &[u64]) -> Result<Vec<u8>, ProtocolError> {
        if candidates.len() != self.candidate_count as usize {
            return Err(ProtocolError::CandidateCountMismatch {
                got: candidates.len(),
                declared: self.candidate_count,
            });
        }
        let arr_len = (self.candidate_count as u64)
            .checked_mul(CANDIDATE_STRIDE as u64)
            .ok_or(ProtocolError::Overflow)?;
        let total = (PARAMS_HEADER_BYTES as u64)
            .checked_add(arr_len)
            .ok_or(ProtocolError::Overflow)?;
        let mut out = Vec::with_capacity(total as usize);
        let mut hdr = *self;
        hdr.blob_total_bytes = total;
        hdr.header_crc32 = 0;
        let head = hdr.to_bytes();
        hdr.header_crc32 = crc32(&head[0..PARAMS_CRC_RANGE_END]);
        out.extend_from_slice(&hdr.to_bytes());
        for c in candidates {
            out.extend_from_slice(&c.to_le_bytes());
        }
        Ok(out)
    }

    /// Decode a params blob (transport only; no validation).
    pub fn from_blob_bytes(bytes: &[u8]) -> Result<(Self, Vec<u64>), ProtocolError> {
        if bytes.len() < PARAMS_HEADER_BYTES {
            return Err(ProtocolError::BufferTooShort {
                need: PARAMS_HEADER_BYTES,
                got: bytes.len(),
            });
        }
        let hdr = Self::from_bytes(&bytes[0..PARAMS_HEADER_BYTES])?;
        // --- Validation phase (no allocation) ---
        if hdr.magic != PARAMS_MAGIC {
            return Err(ProtocolError::BadMagic { got: hdr.magic });
        }
        if hdr.version != PROTOCOL_VERSION {
            return Err(ProtocolError::BadVersion {
                got: hdr.version,
                expected: PROTOCOL_VERSION,
            });
        }
        if hdr.header_bytes != PARAMS_HEADER_BYTES as u16 {
            return Err(ProtocolError::BadHeaderBytes {
                got: hdr.header_bytes,
                expected: PARAMS_HEADER_BYTES as u16,
            });
        }
        if hdr.candidate_off != CANDIDATE_OFF as u32 {
            return Err(ProtocolError::BadCandidateOff {
                got: hdr.candidate_off,
                expected: CANDIDATE_OFF as u32,
            });
        }
        if hdr.candidate_stride != CANDIDATE_STRIDE as u16 {
            return Err(ProtocolError::BadCandidateStride {
                got: hdr.candidate_stride,
                expected: CANDIDATE_STRIDE as u16,
            });
        }
        if hdr.candidate_count > MAX_CANDIDATE_COUNT {
            return Err(ProtocolError::CountTooLarge {
                got: hdr.candidate_count as u64,
                max: MAX_CANDIDATE_COUNT as u64,
            });
        }
        if hdr.blob_total_bytes > MAX_BLOB_BYTES as u64 {
            return Err(ProtocolError::CountTooLarge {
                got: hdr.blob_total_bytes,
                max: MAX_BLOB_BYTES as u64,
            });
        }
        if bytes.len() as u64 != hdr.blob_total_bytes {
            return Err(ProtocolError::BadBlobTotalBytes {
                got: bytes.len() as u64,
            });
        }
        let arr_len = (hdr.candidate_count as u64)
            .checked_mul(CANDIDATE_STRIDE as u64)
            .ok_or(ProtocolError::Overflow)?;
        let end = (hdr.candidate_off as u64)
            .checked_add(arr_len)
            .ok_or(ProtocolError::Overflow)?;
        if end > hdr.blob_total_bytes {
            return Err(ProtocolError::OutOfBounds {
                start: hdr.candidate_off as u64,
                end,
                total: hdr.blob_total_bytes,
            });
        }
        // --- Allocation phase (bounds already proven) ---
        let mut candidates = Vec::with_capacity(hdr.candidate_count as usize);
        let mut pos = hdr.candidate_off as usize;
        for _ in 0..hdr.candidate_count {
            // Slice in-bounds: pos+8 <= end <= blob_total_bytes == bytes.len().
            candidates.push(u64::from_le_bytes(
                bytes[pos..pos + CANDIDATE_STRIDE].try_into().unwrap(),
            ));
            pos += CANDIDATE_STRIDE;
        }
        Ok((hdr, candidates))
    }

    fn to_bytes(&self) -> [u8; PARAMS_HEADER_BYTES] {
        let mut out = [0u8; PARAMS_HEADER_BYTES];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.header_bytes.to_le_bytes());
        out[8..16].copy_from_slice(&self.blob_total_bytes.to_le_bytes());
        out[16..24].copy_from_slice(&self.blob_base_va.to_le_bytes());
        out[24..28].copy_from_slice(&self.candidate_off.to_le_bytes());
        out[28..32].copy_from_slice(&self.candidate_count.to_le_bytes());
        out[32..34].copy_from_slice(&self.candidate_stride.to_le_bytes());
        out[34..36].copy_from_slice(&self.options_flags.to_le_bytes());
        out[36..38].copy_from_slice(&self.probe_span.to_le_bytes());
        out[38..40].copy_from_slice(&self._reserved.to_le_bytes());
        out[40..48].copy_from_slice(&self.result_nonce.to_le_bytes());
        out[48..56].copy_from_slice(&self.result_bytes.to_le_bytes());
        out[56..60].copy_from_slice(&self.header_crc32.to_le_bytes());
        out[60..64].copy_from_slice(&self._reserved2.to_le_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < PARAMS_HEADER_BYTES {
            return Err(ProtocolError::BufferTooShort {
                need: PARAMS_HEADER_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self {
            magic: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            version: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            header_bytes: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            blob_total_bytes: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            blob_base_va: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            candidate_off: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            candidate_count: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
            candidate_stride: u16::from_le_bytes(bytes[32..34].try_into().unwrap()),
            options_flags: u16::from_le_bytes(bytes[34..36].try_into().unwrap()),
            probe_span: u16::from_le_bytes(bytes[36..38].try_into().unwrap()),
            _reserved: u16::from_le_bytes(bytes[38..40].try_into().unwrap()),
            result_nonce: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            result_bytes: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
            header_crc32: u32::from_le_bytes(bytes[56..60].try_into().unwrap()),
            _reserved2: u32::from_le_bytes(bytes[60..64].try_into().unwrap()),
        })
    }

    /// Full fail-closed validation of a decoded params blob + candidates.
    pub fn validate(&self, candidates: &[u64]) -> Result<(), ProtocolError> {
        if self.magic != PARAMS_MAGIC {
            return Err(ProtocolError::BadMagic { got: self.magic });
        }
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::BadVersion {
                got: self.version,
                expected: PROTOCOL_VERSION,
            });
        }
        if self.header_bytes != PARAMS_HEADER_BYTES as u16 {
            return Err(ProtocolError::BadHeaderBytes {
                got: self.header_bytes,
                expected: PARAMS_HEADER_BYTES as u16,
            });
        }
        if self.candidate_off != CANDIDATE_OFF as u32 {
            return Err(ProtocolError::BadCandidateOff {
                got: self.candidate_off,
                expected: CANDIDATE_OFF as u32,
            });
        }
        if self.candidate_stride != CANDIDATE_STRIDE as u16 {
            return Err(ProtocolError::BadCandidateStride {
                got: self.candidate_stride,
                expected: CANDIDATE_STRIDE as u16,
            });
        }
        if self.probe_span < MIN_PROBE_SPAN || self.probe_span > MAX_PROBE_SPAN {
            return Err(ProtocolError::BadProbeSpan {
                got: self.probe_span,
                min: MIN_PROBE_SPAN,
                max: MAX_PROBE_SPAN,
            });
        }
        if self.options_flags & !OPTION_KNOWN_MASK != 0 {
            return Err(ProtocolError::UnknownOptionFlags {
                got: self.options_flags,
            });
        }
        if self.result_nonce == 0 {
            return Err(ProtocolError::ZeroNonce);
        }
        if !is_canonical_user_va(self.blob_base_va) {
            return Err(ProtocolError::NonCanonicalVa {
                va: self.blob_base_va,
            });
        }
        if self.candidate_count > MAX_CANDIDATE_COUNT {
            return Err(ProtocolError::CountTooLarge {
                got: self.candidate_count as u64,
                max: MAX_CANDIDATE_COUNT as u64,
            });
        }
        if candidates.len() != self.candidate_count as usize {
            return Err(ProtocolError::CandidateCountMismatch {
                got: candidates.len(),
                declared: self.candidate_count,
            });
        }
        let arr_len = (self.candidate_count as u64)
            .checked_mul(CANDIDATE_STRIDE as u64)
            .ok_or(ProtocolError::Overflow)?;
        let expected_total = (PARAMS_HEADER_BYTES as u64)
            .checked_add(arr_len)
            .ok_or(ProtocolError::Overflow)?;
        if self.blob_total_bytes != expected_total {
            return Err(ProtocolError::BadBlobTotalBytes {
                got: self.blob_total_bytes,
            });
        }
        if self.blob_total_bytes as usize > MAX_BLOB_BYTES {
            return Err(ProtocolError::CountTooLarge {
                got: self.blob_total_bytes,
                max: MAX_BLOB_BYTES as u64,
            });
        }
        let capacity = (self.candidate_count as u64)
            .checked_mul(PROBE_RESULT_BYTES as u64)
            .and_then(|v| v.checked_add(MIN_SECTION_HEADER_BYTES as u64))
            .ok_or(ProtocolError::Overflow)?;
        if self.result_bytes != capacity {
            return Err(ProtocolError::BadResultBytes {
                got: self.result_bytes,
            });
        }
        if self.result_bytes > MAX_RESULT_SECTION_BYTES {
            return Err(ProtocolError::CountTooLarge {
                got: self.result_bytes,
                max: MAX_RESULT_SECTION_BYTES,
            });
        }
        // Header CRC: recompute over [0x00, 0x38).
        let mut head = [0u8; PARAMS_HEADER_BYTES];
        head.copy_from_slice(&self.to_bytes());
        let computed = crc32(&head[0..PARAMS_CRC_RANGE_END]);
        if computed != self.header_crc32 {
            return Err(ProtocolError::CrcMismatch {
                stored: self.header_crc32,
                computed,
            });
        }
        // Candidate array: canonical user VAs, non-zero, no page crossing.
        for &va in candidates {
            if !is_canonical_user_va(va) {
                return Err(ProtocolError::NonCanonicalVa { va });
            }
            if !page_span_fits(va, self.probe_span) {
                return Err(ProtocolError::PageCross {
                    va,
                    span: self.probe_span,
                });
            }
        }
        Ok(())
    }
}
/// Controller-side expected identity used to verify a result section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityExpectation {
    pub nonce: u64,
    pub target_pid: u32,
    pub owner_pid: u32,
    pub session_id: [u8; WALKER_SESSION_ID_BYTES],
    pub section_bytes: u64,
}

/// Mapping identity header (first 0x38 bytes of the result section).
///
/// Layout (little-endian)
/// ----------------------
/// 0x00 magic u32 "MIDA"
/// 0x04 version u16 2
/// 0x06 _reserved u16 0
/// 0x08 section_bytes u64 total section size
/// 0x10 target_pid u32 target process id
/// 0x14 owner_pid u32 controller process id (echo)
/// 0x18 nonce u64 must equal params.result_nonce
/// 0x20 session_id 16 derive_session_id(...)
/// 0x30 header_crc32 u32 CRC32 of [0x00, 0x30)
/// 0x34 _reserved2 u32 0
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingIdentityHeaderV2 {
    pub magic: u32,
    pub version: u16,
    pub _reserved: u16,
    pub section_bytes: u64,
    pub target_pid: u32,
    pub owner_pid: u32,
    pub nonce: u64,
    pub session_id: [u8; WALKER_SESSION_ID_BYTES],
    pub header_crc32: u32,
    pub _reserved2: u32,
}

impl MappingIdentityHeaderV2 {
    /// Fixed identity header size.
    pub const BYTES: usize = IDENTITY_HEADER_BYTES;

    pub fn new(
        section_bytes: u64,
        target_pid: u32,
        owner_pid: u32,
        nonce: u64,
        session_id: [u8; WALKER_SESSION_ID_BYTES],
    ) -> Self {
        Self {
            magic: IDENTITY_MAGIC,
            version: PROTOCOL_VERSION,
            _reserved: 0,
            section_bytes,
            target_pid,
            owner_pid,
            nonce,
            session_id,
            header_crc32: 0,
            _reserved2: 0,
        }
    }

    fn to_bytes(&self) -> [u8; IDENTITY_HEADER_BYTES] {
        let mut out = [0u8; IDENTITY_HEADER_BYTES];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self._reserved.to_le_bytes());
        out[8..16].copy_from_slice(&self.section_bytes.to_le_bytes());
        out[16..20].copy_from_slice(&self.target_pid.to_le_bytes());
        out[20..24].copy_from_slice(&self.owner_pid.to_le_bytes());
        out[24..32].copy_from_slice(&self.nonce.to_le_bytes());
        out[32..48].copy_from_slice(&self.session_id);
        out[48..52].copy_from_slice(&self.header_crc32.to_le_bytes());
        out[52..56].copy_from_slice(&self._reserved2.to_le_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < IDENTITY_HEADER_BYTES {
            return Err(ProtocolError::BufferTooShort {
                need: IDENTITY_HEADER_BYTES,
                got: bytes.len(),
            });
        }
        let mut session_id = [0u8; WALKER_SESSION_ID_BYTES];
        session_id.copy_from_slice(&bytes[32..48]);
        Ok(Self {
            magic: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            version: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            _reserved: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            section_bytes: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            target_pid: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            owner_pid: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            nonce: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            session_id,
            header_crc32: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
            _reserved2: u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
        })
    }

    /// Controller-side verification: magic/version/CRC plus the full echo set
    /// (nonce, target PID, owner PID, session id, section size).
    pub fn validate_controller(&self, expected: &IdentityExpectation) -> Result<(), ProtocolError> {
        self.validate_common()?;
        if self.nonce != expected.nonce {
            return Err(ProtocolError::IdentityMismatch {
                what: "nonce",
                expected: expected.nonce,
                got: self.nonce,
            });
        }
        if self.target_pid != expected.target_pid {
            return Err(ProtocolError::IdentityMismatch {
                what: "target_pid",
                expected: expected.target_pid as u64,
                got: self.target_pid as u64,
            });
        }
        if self.owner_pid != expected.owner_pid {
            return Err(ProtocolError::IdentityMismatch {
                what: "owner_pid",
                expected: expected.owner_pid as u64,
                got: self.owner_pid as u64,
            });
        }
        if self.session_id != expected.session_id {
            return Err(ProtocolError::SessionIdMismatch);
        }
        if self.section_bytes != expected.section_bytes {
            return Err(ProtocolError::IdentityMismatch {
                what: "section_bytes",
                expected: expected.section_bytes,
                got: self.section_bytes,
            });
        }
        Ok(())
    }

    /// Target-side verification: the target cannot know the controller PID,
    /// so it checks magic/version/CRC, the nonce echoed from the params blob,
    /// the target PID (must equal its own PID) and the section size.
    pub fn validate_target(
        &self,
        nonce: u64,
        my_pid: u32,
        session_id: [u8; WALKER_SESSION_ID_BYTES],
        section_bytes: u64,
    ) -> Result<(), ProtocolError> {
        self.validate_common()?;
        if self.nonce != nonce {
            return Err(ProtocolError::IdentityMismatch {
                what: "nonce",
                expected: nonce,
                got: self.nonce,
            });
        }
        if self.target_pid != my_pid {
            return Err(ProtocolError::IdentityMismatch {
                what: "target_pid",
                expected: my_pid as u64,
                got: self.target_pid as u64,
            });
        }
        if self.session_id != session_id {
            return Err(ProtocolError::SessionIdMismatch);
        }
        if self.section_bytes != section_bytes {
            return Err(ProtocolError::IdentityMismatch {
                what: "section_bytes",
                expected: section_bytes,
                got: self.section_bytes,
            });
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), ProtocolError> {
        if self.magic != IDENTITY_MAGIC {
            return Err(ProtocolError::BadMagic { got: self.magic });
        }
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::BadVersion {
                got: self.version,
                expected: PROTOCOL_VERSION,
            });
        }
        let mut head = [0u8; IDENTITY_HEADER_BYTES];
        head.copy_from_slice(&self.to_bytes());
        let computed = crc32(&head[0..48]);
        if computed != self.header_crc32 {
            return Err(ProtocolError::CrcMismatch {
                stored: self.header_crc32,
                computed,
            });
        }
        Ok(())
    }
}
/// Result section header (0x28 bytes, immediately after the identity header).
///
/// Layout (little-endian)
/// ----------------------
/// 0x00 magic u32 "WRES"
/// 0x04 version u16 2
/// 0x06 _reserved u16 0
/// 0x08 section_bytes u64 total section size
/// 0x10 result_count u32 records written so far
/// 0x14 result_stride u32 40 (= PROBE_RESULT_BYTES)
/// 0x18 results_off u32 >= 96, 8-aligned
/// 0x1C walker_status u32 closed status set
/// 0x20 payload_crc32 u32 CRC32 of the result payload region
/// 0x24 completed_flag u32 pending/done/abort
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultSectionHeaderV2 {
    pub magic: u32,
    pub version: u16,
    pub _reserved: u16,
    pub section_bytes: u64,
    pub result_count: u32,
    pub result_stride: u32,
    pub results_off: u32,
    pub walker_status: u32,
    pub payload_crc32: u32,
    pub completed_flag: u32,
}

impl ResultSectionHeaderV2 {
    /// Fixed result header size.
    pub const BYTES: usize = RESULT_HEADER_BYTES;

    /// Fresh result header (initial state: pending, zeroed).
    pub fn new(section_bytes: u64, result_capacity: u32) -> Result<Self, ProtocolError> {
        let capacity = (result_capacity as u64)
            .checked_mul(PROBE_RESULT_BYTES as u64)
            .and_then(|v| v.checked_add(MIN_SECTION_HEADER_BYTES as u64))
            .ok_or(ProtocolError::Overflow)?;
        if section_bytes != capacity {
            return Err(ProtocolError::BadSectionBytes { got: section_bytes });
        }
        if section_bytes > MAX_RESULT_SECTION_BYTES {
            return Err(ProtocolError::CountTooLarge {
                got: section_bytes,
                max: MAX_RESULT_SECTION_BYTES,
            });
        }
        Ok(Self {
            magic: RESULT_MAGIC,
            version: PROTOCOL_VERSION,
            _reserved: 0,
            section_bytes,
            result_count: 0,
            result_stride: PROBE_RESULT_BYTES as u32,
            results_off: MIN_SECTION_HEADER_BYTES as u32,
            walker_status: WALKER_STATUS_OK,
            payload_crc32: 0,
            completed_flag: COMPLETED_FLAG_PENDING,
        })
    }

    fn to_bytes(&self) -> [u8; RESULT_HEADER_BYTES] {
        let mut out = [0u8; RESULT_HEADER_BYTES];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self._reserved.to_le_bytes());
        out[8..16].copy_from_slice(&self.section_bytes.to_le_bytes());
        out[16..20].copy_from_slice(&self.result_count.to_le_bytes());
        out[20..24].copy_from_slice(&self.result_stride.to_le_bytes());
        out[24..28].copy_from_slice(&self.results_off.to_le_bytes());
        out[28..32].copy_from_slice(&self.walker_status.to_le_bytes());
        out[32..36].copy_from_slice(&self.payload_crc32.to_le_bytes());
        out[36..40].copy_from_slice(&self.completed_flag.to_le_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < RESULT_HEADER_BYTES {
            return Err(ProtocolError::BufferTooShort {
                need: RESULT_HEADER_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self {
            magic: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            version: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            _reserved: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            section_bytes: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            result_count: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            result_stride: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            results_off: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            walker_status: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
            payload_crc32: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            completed_flag: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
        })
    }

    /// Structural validation of the result header (closed sets, offsets).
    pub fn validate_layout(&self) -> Result<(), ProtocolError> {
        if self.magic != RESULT_MAGIC {
            return Err(ProtocolError::BadMagic { got: self.magic });
        }
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::BadVersion {
                got: self.version,
                expected: PROTOCOL_VERSION,
            });
        }
        if self.result_stride != PROBE_RESULT_BYTES as u32 {
            return Err(ProtocolError::BadResultStride {
                got: self.result_stride,
                expected: PROBE_RESULT_BYTES as u32,
            });
        }
        if self.results_off < MIN_SECTION_HEADER_BYTES as u32 {
            return Err(ProtocolError::ResultsOffTooSmall {
                got: self.results_off,
                min: MIN_SECTION_HEADER_BYTES as u32,
            });
        }
        if self.results_off % 8 != 0 {
            return Err(ProtocolError::ResultsOffUnaligned {
                got: self.results_off,
            });
        }
        if self.walker_status > WALKER_STATUS_MAX {
            return Err(ProtocolError::UnknownWalkerStatus {
                got: self.walker_status,
            });
        }
        match self.completed_flag {
            COMPLETED_FLAG_PENDING | COMPLETED_FLAG_DONE => {
                if self.walker_status != WALKER_STATUS_OK {
                    return Err(ProtocolError::BadStatusForState {
                        got: self.walker_status,
                        flag: self.completed_flag,
                    });
                }
            }
            COMPLETED_FLAG_ABORT => {
                if self.walker_status == WALKER_STATUS_OK {
                    return Err(ProtocolError::BadStatusForState {
                        got: self.walker_status,
                        flag: self.completed_flag,
                    });
                }
            }
            other => return Err(ProtocolError::BadCompletedFlag { got: other }),
        }
        Ok(())
    }
}

/// Fixed-layout per-candidate probe record (0x28 bytes, no embedded pointers).
///
/// Layout (little-endian)
/// ----------------------
/// 0x00 probe_va u64 probed target VA
/// 0x08 classification u32 closed classification set
/// 0x0C flags u8 closed flag set
/// 0x0D retry_count u8 retries used (<= 1 by contract)
/// 0x0E probe_span u16 bytes actually read
/// 0x10 observed 16 first bytes observed
/// 0x20 latency_us u32 probe latency
/// 0x24 _reserved u32 0
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeResultV2 {
    pub probe_va: u64,
    pub classification: u32,
    pub flags: u8,
    pub retry_count: u8,
    pub probe_span: u16,
    pub observed: [u8; 16],
    pub latency_us: u32,
    pub _reserved: u32,
}

impl ProbeResultV2 {
    /// Fixed probe result size.
    pub const BYTES: usize = PROBE_RESULT_BYTES;

    pub fn new(
        probe_va: u64,
        classification: u32,
        flags: u8,
        retry_count: u8,
        observed: [u8; 16],
    ) -> Self {
        Self {
            probe_va,
            classification,
            flags,
            retry_count,
            probe_span: 0, // set by caller via set_probe_span
            observed,
            latency_us: 0,
            _reserved: 0,
        }
    }

    pub fn set_probe_span(&mut self, span: u16) {
        self.probe_span = span;
    }

    pub fn set_latency_us(&mut self, latency_us: u32) {
        self.latency_us = latency_us;
    }

    fn to_bytes(&self) -> [u8; PROBE_RESULT_BYTES] {
        let mut out = [0u8; PROBE_RESULT_BYTES];
        out[0..8].copy_from_slice(&self.probe_va.to_le_bytes());
        out[8..12].copy_from_slice(&self.classification.to_le_bytes());
        out[12] = self.flags;
        out[13] = self.retry_count;
        out[14..16].copy_from_slice(&self.probe_span.to_le_bytes());
        out[16..32].copy_from_slice(&self.observed);
        out[32..36].copy_from_slice(&self.latency_us.to_le_bytes());
        out[36..40].copy_from_slice(&self._reserved.to_le_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < PROBE_RESULT_BYTES {
            return Err(ProtocolError::BufferTooShort {
                need: PROBE_RESULT_BYTES,
                got: bytes.len(),
            });
        }
        let mut observed = [0u8; 16];
        observed.copy_from_slice(&bytes[16..32]);
        Ok(Self {
            probe_va: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            classification: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            flags: bytes[12],
            retry_count: bytes[13],
            probe_span: u16::from_le_bytes(bytes[14..16].try_into().unwrap()),
            observed,
            latency_us: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            _reserved: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
        })
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !is_canonical_user_va(self.probe_va) {
            return Err(ProtocolError::NonCanonicalVa {
                va: self.probe_va,
            });
        }
        if self.classification > CLASSIFICATION_MAX {
            return Err(ProtocolError::BadClassification {
                got: self.classification,
            });
        }
        if self.flags & !RESULT_FLAG_KNOWN_MASK != 0 {
            return Err(ProtocolError::UnknownResultFlags { got: self.flags });
        }
        if self.probe_span < MIN_PROBE_SPAN || self.probe_span > MAX_PROBE_SPAN {
            return Err(ProtocolError::BadProbeSpan {
                got: self.probe_span,
                min: MIN_PROBE_SPAN,
                max: MAX_PROBE_SPAN,
            });
        }
        if self.retry_count > 1 {
            return Err(ProtocolError::BadRetryCount { got: self.retry_count });
        }
        if self._reserved != 0 {
            return Err(ProtocolError::BadReserved {
                got: self._reserved,
            });
        }
        Ok(())
    }
}

/// Encode a complete result section:
/// identity header ++ result header ++ result payload.
pub fn encode_section(
    identity: &MappingIdentityHeaderV2,
    header: &ResultSectionHeaderV2,
    results: &[ProbeResultV2],
) -> Result<Vec<u8>, ProtocolError> {
    // Entry validation: encode_section is a VALIDATED CONSTRUCTOR. Every
    // field that validate_section / parse_section would reject later must be
    // rejected here, so the API can never emit a section that the frozen wire
    // contract rejects, and never allocate from an untrusted section_bytes.
    //
    // Identity: magic/version/reserved, section_bytes consistency (checked
    // against header below), CRC over [0, 48) is recomputed at encode time.
    if identity.magic != IDENTITY_MAGIC {
        return Err(ProtocolError::BadMagic { got: identity.magic });
    }
    if identity.version != PROTOCOL_VERSION {
        return Err(ProtocolError::BadVersion {
            got: identity.version,
            expected: PROTOCOL_VERSION,
        });
    }
    if identity._reserved != 0 {
        return Err(ProtocolError::BadReserved {
            got: identity._reserved as u32,
        });
    }
    // Header: closed sets and layout (magic/version/stride/status/flag/offs).
    header.validate_layout()?;
    // section_bytes is a CAPACITY: MIN_SECTION_HEADER_BYTES + n*40 for some
    // n in [0, MAX_CANDIDATE_COUNT]; result_count <= n.
    if header.section_bytes > MAX_RESULT_SECTION_BYTES {
        return Err(ProtocolError::CountTooLarge {
            got: header.section_bytes,
            max: MAX_RESULT_SECTION_BYTES,
        });
    }
    if header.section_bytes < MIN_SECTION_HEADER_BYTES as u64 {
        return Err(ProtocolError::BadSectionBytes {
            got: header.section_bytes,
        });
    }
    let capacity_n = header.section_bytes - MIN_SECTION_HEADER_BYTES as u64;
    if capacity_n % PROBE_RESULT_BYTES as u64 != 0 {
        return Err(ProtocolError::BadSectionBytes {
            got: header.section_bytes,
        });
    }
    let capacity = (capacity_n / PROBE_RESULT_BYTES as u64) as u32;
    if capacity > MAX_CANDIDATE_COUNT {
        return Err(ProtocolError::CountTooLarge {
            got: header.section_bytes,
            max: MAX_RESULT_SECTION_BYTES,
        });
    }
    if header.section_bytes != identity.section_bytes {
        return Err(ProtocolError::BadSectionBytes {
            got: header.section_bytes,
        });
    }
    if header.result_count > capacity {
        return Err(ProtocolError::ResultCountExceedsCapacity {
            got: header.result_count,
            capacity,
        });
    }
    if results.len() != header.result_count as usize {
        return Err(ProtocolError::ResultCountExceedsCapacity {
            got: results.len() as u32,
            capacity: header.result_count,
        });
    }
    let payload_len = (header.result_count as u64)
        .checked_mul(PROBE_RESULT_BYTES as u64)
        .ok_or(ProtocolError::Overflow)?;
    let end = (header.results_off as u64)
        .checked_add(payload_len)
        .ok_or(ProtocolError::Overflow)?;
    if end > header.section_bytes {
        return Err(ProtocolError::OutOfBounds {
            start: header.results_off as u64,
            end,
            total: header.section_bytes,
        });
    }
    // Every result record must itself satisfy the frozen per-record contract
    // (canonical VA, classification/flags closed sets, span range, retry cap,
    // reserved zero) BEFORE it is serialized.
    for r in results {
        r.validate()?;
    }
    let mut out = Vec::with_capacity(header.section_bytes as usize);
    // Identity header with CRC computed over [0, 48).
    let mut ident = *identity;
    ident.header_crc32 = 0;
    let mut ib = ident.to_bytes();
    ident.header_crc32 = crc32(&ib[0..48]);
    ib = ident.to_bytes();
    out.extend_from_slice(&ib);
    // Result header with payload CRC computed over the payload region.
    let mut hdr = *header;
    hdr.payload_crc32 = 0;
    let mut payload = Vec::with_capacity(payload_len as usize);
    for r in results {
        payload.extend_from_slice(&r.to_bytes());
    }
    hdr.payload_crc32 = crc32(&payload);
    out.extend_from_slice(&hdr.to_bytes());
    out.extend_from_slice(&payload);
    // Section size contract: the encoded buffer MUST be exactly
    // section_bytes (identity + header + capacity * stride), regardless
    // of how many results were written. Unwritten capacity is zero-filled.
    if out.len() > header.section_bytes as usize {
        return Err(ProtocolError::OutOfBounds {
            start: out.len() as u64,
            end: header.section_bytes,
            total: header.section_bytes,
        });
    }
    out.resize(header.section_bytes as usize, 0);
    Ok(out)
}

/// Decode a complete result section (transport only; no validation).
///
/// A section in pending state exposes no payload: results is empty.
pub fn parse_section(
    bytes: &[u8],
) -> Result<
    (
        MappingIdentityHeaderV2,
        ResultSectionHeaderV2,
        Vec<ProbeResultV2>,
    ),
    ProtocolError,
> {
    if bytes.len() < MIN_SECTION_HEADER_BYTES {
        return Err(ProtocolError::BufferTooShort {
            need: MIN_SECTION_HEADER_BYTES,
            got: bytes.len(),
        });
    }
    let identity = MappingIdentityHeaderV2::from_bytes(&bytes[0..IDENTITY_HEADER_BYTES])?;
    let header = ResultSectionHeaderV2::from_bytes(
        &bytes[IDENTITY_HEADER_BYTES..IDENTITY_HEADER_BYTES + RESULT_HEADER_BYTES],
    )?;
    // --- Validation phase (no allocation) ---
    // Fixed fields + closed sets + completed_flag/status consistency.
    header.validate_layout()?;
    if header.section_bytes != identity.section_bytes {
        return Err(ProtocolError::BadSectionBytes {
            got: header.section_bytes,
        });
    }
    if bytes.len() as u64 != header.section_bytes {
        return Err(ProtocolError::BadSectionBytes {
            got: bytes.len() as u64,
        });
    }
    if header.section_bytes > MAX_RESULT_SECTION_BYTES {
        return Err(ProtocolError::CountTooLarge {
            got: header.section_bytes,
            max: MAX_RESULT_SECTION_BYTES,
        });
    }
    if header.result_count > MAX_CANDIDATE_COUNT {
        return Err(ProtocolError::CountTooLarge {
            got: header.result_count as u64,
            max: MAX_CANDIDATE_COUNT as u64,
        });
    }
    if header.completed_flag == COMPLETED_FLAG_PENDING {
        if header.result_count != 0 {
            return Err(ProtocolError::InconsistentPendingCount {
                got: header.result_count,
            });
        }
        return Ok((identity, header, Vec::new()));
    }
    // result_stride is validated by validate_layout() == PROBE_RESULT_BYTES,
    // so count*stride is count*40 with count <= 4096: no overflow possible.
    let payload_len = (header.result_count as u64)
        .checked_mul(PROBE_RESULT_BYTES as u64)
        .ok_or(ProtocolError::Overflow)?;
    let end = (header.results_off as u64)
        .checked_add(payload_len)
        .ok_or(ProtocolError::Overflow)?;
    if end > header.section_bytes {
        return Err(ProtocolError::OutOfBounds {
            start: header.results_off as u64,
            end,
            total: header.section_bytes,
        });
    }
    // --- Allocation phase (bounds already proven) ---
    let mut results = Vec::with_capacity(header.result_count as usize);
    let mut pos = header.results_off as usize;
    for _ in 0..header.result_count {
        // Slice in-bounds: pos+40 <= end <= section_bytes == bytes.len().
        results.push(ProbeResultV2::from_bytes(
            &bytes[pos..pos + PROBE_RESULT_BYTES],
        )?);
        pos += PROBE_RESULT_BYTES;
    }
    Ok((identity, header, results))
}

/// Full fail-closed validation of a decoded result section against the
/// controller expectation. result_capacity must equal the params candidate
/// count (capacity = one result per candidate).
pub fn validate_section(
    identity: &MappingIdentityHeaderV2,
    header: &ResultSectionHeaderV2,
    results: &[ProbeResultV2],
    expected: &IdentityExpectation,
    result_capacity: u32,
) -> Result<(), ProtocolError> {
    identity.validate_controller(expected)?;
    header.validate_layout()?;
    if header.section_bytes != identity.section_bytes {
        return Err(ProtocolError::BadSectionBytes {
            got: header.section_bytes,
        });
    }
    let expected_bytes = (result_capacity as u64)
        .checked_mul(PROBE_RESULT_BYTES as u64)
        .and_then(|v| v.checked_add(MIN_SECTION_HEADER_BYTES as u64))
        .ok_or(ProtocolError::Overflow)?;
    if header.section_bytes != expected_bytes {
        return Err(ProtocolError::BadSectionBytes {
            got: header.section_bytes,
        });
    }
    if header.result_count > result_capacity {
        return Err(ProtocolError::ResultCountExceedsCapacity {
            got: header.result_count,
            capacity: result_capacity,
        });
    }
    if header.completed_flag == COMPLETED_FLAG_PENDING {
        if header.result_count != 0 {
            return Err(ProtocolError::InconsistentPendingCount {
                got: header.result_count,
            });
        }
        return Ok(());
    }
    if results.len() != header.result_count as usize {
        return Err(ProtocolError::ResultCountExceedsCapacity {
            got: results.len() as u32,
            capacity: header.result_count,
        });
    }
    // --- Self-contained payload bounds (does not rely on the caller) ---
    // results.len() <= result_capacity <= MAX_CANDIDATE_COUNT, so the
    // multiplication below cannot overflow; checked anyway for the contract.
    let payload_len = (results.len() as u64)
        .checked_mul(PROBE_RESULT_BYTES as u64)
        .ok_or(ProtocolError::Overflow)?;
    let payload_end = (header.results_off as u64)
        .checked_add(payload_len)
        .ok_or(ProtocolError::Overflow)?;
    if payload_end > header.section_bytes {
        return Err(ProtocolError::OutOfBounds {
            start: header.results_off as u64,
            end: payload_end,
            total: header.section_bytes,
        });
    }
    // Payload CRC covers [results_off, results_off + count * stride).
    let mut payload = Vec::with_capacity(results.len() * PROBE_RESULT_BYTES);
    for r in results {
        r.validate()?;
        payload.extend_from_slice(&r.to_bytes());
    }
    let computed = crc32(&payload);
    if computed != header.payload_crc32 {
        return Err(ProtocolError::CrcMismatch {
            stored: header.payload_crc32,
            computed,
        });
    }
    Ok(())
}