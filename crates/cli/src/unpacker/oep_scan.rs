//! Live memory OEP scan — find a unique strong MSVC CRT PE-entry wrapper.
//!
//! Fail-closed for `--oep=crt`:
//! - bare `sub rsp, imm8` is never an accepted PE entry
//! - `__scrt_common_main_seh` body alone is never an accepted PE entry
//! - weak E8/E9 first-match is diagnostic only
//! - zero or multiple equally-strong wrappers → no accepted candidate
//!
//! Pure scanner [`scan_crt_entry_candidate`] does not touch process memory.
//! Live path reads full executable `.text` (chunked, capped) then calls the pure scanner.

use super::session::ProcessSession;
use mida_core::DebuggerCore;
use mida_pe::{OepPolicy, PeSection};
use tracing::{info, warn};

/// Maximum bytes of decrypted `.text` the live path will attempt to read.
const MAX_TEXT_READ: usize = 16 * 1024 * 1024;
/// Chunk size for live reads (overlap covers the 18-byte wrapper across boundaries).
const READ_CHUNK: usize = 0x100_000;
/// Overlap between consecutive chunks (≥ wrapper length).
const CHUNK_OVERLAP: usize = 32;
/// Prefer a unique strong candidate within this distance of `captured_rva`.
const CAPTURED_NEAR: u32 = 0x80;
/// Strong MSVC x64 PE-entry wrapper size:
/// `sub rsp,28 / call rel32 / add rsp,28 / jmp rel32` = 18 bytes.
const WRAPPER_LEN: usize = 18;

// ---------------------------------------------------------------------------
// Public pure types / API
// ---------------------------------------------------------------------------

/// Half-open executable RVA range `[rva_start, rva_end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutableRange {
    pub rva_start: u32,
    pub rva_end: u32,
}

impl ExecutableRange {
    pub fn contains(self, rva: u32) -> bool {
        rva >= self.rva_start && rva < self.rva_end
    }
}

/// Confidence for CRT entry candidates. Only `Strong` may be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrtConfidence {
    Strong,
    WeakDiagnostic,
}

/// One CRT OEP candidate (accepted or rejected/diagnostic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrtCandidate {
    pub rva: u32,
    pub rule: &'static str,
    pub confidence: CrtConfidence,
    pub call_target_rva: Option<u32>,
    pub jmp_target_rva: Option<u32>,
    pub rejection: Option<&'static str>,
}

/// Result of pure CRT PE-entry scan (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanCrtResult {
    /// Exactly one unique strong wrapper (after captured-neighborhood preference).
    Accepted(CrtCandidate),
    /// Two or more equally strong wrappers; do not first-match.
    Ambiguous {
        candidates: Vec<CrtCandidate>,
        rejected: Vec<CrtCandidate>,
    },
    /// No strong wrapper; weak hits are diagnostic only.
    NotFound { rejected: Vec<CrtCandidate> },
}

impl ScanCrtResult {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn accepted_rva(&self) -> Option<u32> {
        match self {
            ScanCrtResult::Accepted(c) => Some(c.rva),
            _ => None,
        }
    }
}

/// Pure CRT PE-entry scanner (no process / session dependency).
///
/// `text_bytes` are image bytes starting at `text_rva`.
/// `captured_rva` is the frozen first decrypted `.text` RIP (optional preference).
/// `executable_ranges` are used to validate call/jmp targets.
///
/// **Important:** an accepted RVA is a *synthesized/captured wrapper candidate*,
/// not a claim of absolute “true OEP” for the packed sample.
pub fn scan_crt_entry_candidate(
    text_bytes: &[u8],
    text_rva: u32,
    captured_rva: Option<u32>,
    executable_ranges: &[ExecutableRange],
) -> ScanCrtResult {
    let mut rejected: Vec<CrtCandidate> = Vec::new();
    let mut strong: Vec<CrtCandidate> = Vec::new();

    if text_bytes.len() < WRAPPER_LEN {
        rejected.push(CrtCandidate {
            rva: text_rva,
            rule: "buffer_too_short",
            confidence: CrtConfidence::WeakDiagnostic,
            call_target_rva: None,
            jmp_target_rva: None,
            rejection: Some("text_bytes shorter than wrapper length"),
        });
        return ScanCrtResult::NotFound { rejected };
    }

    // ---- Strong: full MSVC x64 PE-entry wrapper ----
    let scan_end = text_bytes.len().saturating_sub(WRAPPER_LEN - 1);
    for off in 0..scan_end {
        match try_match_strong_wrapper(text_bytes, text_rva, off, executable_ranges) {
            Ok(c) => strong.push(c),
            Err(Some(c)) => rejected.push(c),
            Err(None) => {}
        }
    }

    // ---- Weak diagnostics only (never accepted) ----
    collect_weak_diagnostics(text_bytes, text_rva, &mut rejected);

    if strong.is_empty() {
        return ScanCrtResult::NotFound { rejected };
    }

    // Prefer unique strong candidate at/near captured_rva (wrapper itself or neighborhood).
    if let Some(cap) = captured_rva {
        let near: Vec<CrtCandidate> = strong
            .iter()
            .filter(|c| c.rva.abs_diff(cap) <= CAPTURED_NEAR)
            .cloned()
            .collect();
        if near.len() == 1 {
            return ScanCrtResult::Accepted(near.into_iter().next().unwrap());
        }
        if near.len() > 1 {
            return ScanCrtResult::Ambiguous {
                candidates: near,
                rejected,
            };
        }
        // No near hit: fall through — only accept if global unique.
    }

    if strong.len() == 1 {
        return ScanCrtResult::Accepted(strong.into_iter().next().unwrap());
    }

    ScanCrtResult::Ambiguous {
        candidates: strong,
        rejected,
    }
}

/// Resolve final PE entry VA from policy + scan outcome.
///
/// - `Crt`: fail-closed when `scanned` is `None` (not found / ambiguous / short read).
/// - `Captured`: always `captured_oep` (scanner result ignored).
/// - `Fixed(rva)`: `image_base + rva`.
pub fn resolve_oep_va(
    policy: OepPolicy,
    image_base: usize,
    captured_oep: usize,
    scanned: Option<usize>,
) -> Result<usize, anyhow::Error> {
    match policy {
        OepPolicy::Fixed(rva) => Ok(image_base.wrapping_add(rva as usize)),
        OepPolicy::Captured => Ok(captured_oep),
        OepPolicy::Crt => match scanned {
            Some(va) => Ok(va),
            None => Err(anyhow::anyhow!(
                "--oep=crt fail-closed: no unique strong MSVC CRT PE-entry wrapper \
                 (bare sub rsp / SEH body / weak E8E9 are not accepted; \
                  zero or multiple strong candidates is an error)"
            )),
        },
    }
}

// ---------------------------------------------------------------------------
// Strong wrapper matching
// ---------------------------------------------------------------------------

/// Try to match the strong 18-byte wrapper at `off` within `text_bytes`.
///
/// `Ok(candidate)` — strong valid.
/// `Err(Some(rejected))` — prefix matched but validation failed.
/// `Err(None)` — no prefix match at this offset.
fn try_match_strong_wrapper(
    text_bytes: &[u8],
    text_rva: u32,
    off: usize,
    executable_ranges: &[ExecutableRange],
) -> Result<CrtCandidate, Option<CrtCandidate>> {
    // 48 83 EC 28  E8 xx xx xx xx  48 83 C4 28  E9 xx xx xx xx
    if text_bytes.len() < off + WRAPPER_LEN {
        return Err(None);
    }
    let b = &text_bytes[off..off + WRAPPER_LEN];
    if !(b[0] == 0x48
        && b[1] == 0x83
        && b[2] == 0xEC
        && b[3] == 0x28
        && b[4] == 0xE8
        && b[9] == 0x48
        && b[10] == 0x83
        && b[11] == 0xC4
        && b[12] == 0x28
        && b[13] == 0xE9)
    {
        return Err(None);
    }

    let cand_rva = match text_rva.checked_add(off as u32) {
        Some(r) => r,
        None => {
            return Err(Some(CrtCandidate {
                rva: text_rva,
                rule: "msvc_x64_pe_entry_wrapper",
                confidence: CrtConfidence::WeakDiagnostic,
                call_target_rva: None,
                jmp_target_rva: None,
                rejection: Some("candidate_rva_overflow"),
            }));
        }
    };

    // Reasonable function boundary: start of buffer, or prior byte is INT3/NOP/null/ret-pad.
    if !is_reasonable_function_boundary(text_bytes, off) {
        return Err(Some(CrtCandidate {
            rva: cand_rva,
            rule: "msvc_x64_pe_entry_wrapper",
            confidence: CrtConfidence::WeakDiagnostic,
            call_target_rva: None,
            jmp_target_rva: None,
            rejection: Some("not_a_reasonable_function_boundary"),
        }));
    }

    // call target: next_ip = cand_rva + 9, rel32 at b[5..9]
    let call_rel = i32::from_le_bytes([b[5], b[6], b[7], b[8]]);
    let call_target = match checked_rel32_target(cand_rva.wrapping_add(9), call_rel) {
        Some(t) => t,
        None => {
            return Err(Some(CrtCandidate {
                rva: cand_rva,
                rule: "msvc_x64_pe_entry_wrapper",
                confidence: CrtConfidence::WeakDiagnostic,
                call_target_rva: None,
                jmp_target_rva: None,
                rejection: Some("call_rel32_overflow"),
            }));
        }
    };

    // jmp target: next_ip = cand_rva + 18, rel32 at b[14..18]
    let jmp_rel = i32::from_le_bytes([b[14], b[15], b[16], b[17]]);
    let jmp_target = match checked_rel32_target(cand_rva.wrapping_add(18), jmp_rel) {
        Some(t) => t,
        None => {
            return Err(Some(CrtCandidate {
                rva: cand_rva,
                rule: "msvc_x64_pe_entry_wrapper",
                confidence: CrtConfidence::WeakDiagnostic,
                call_target_rva: Some(call_target),
                jmp_target_rva: None,
                rejection: Some("jmp_rel32_overflow"),
            }));
        }
    };

    if !rva_in_any(call_target, executable_ranges) {
        return Err(Some(CrtCandidate {
            rva: cand_rva,
            rule: "msvc_x64_pe_entry_wrapper",
            confidence: CrtConfidence::WeakDiagnostic,
            call_target_rva: Some(call_target),
            jmp_target_rva: Some(jmp_target),
            rejection: Some("invalid_call_target_not_executable"),
        }));
    }
    if !rva_in_any(jmp_target, executable_ranges) {
        return Err(Some(CrtCandidate {
            rva: cand_rva,
            rule: "msvc_x64_pe_entry_wrapper",
            confidence: CrtConfidence::WeakDiagnostic,
            call_target_rva: Some(call_target),
            jmp_target_rva: Some(jmp_target),
            rejection: Some("invalid_jmp_target_not_executable"),
        }));
    }

    // Candidate itself must sit in an executable range.
    if !rva_in_any(cand_rva, executable_ranges) {
        return Err(Some(CrtCandidate {
            rva: cand_rva,
            rule: "msvc_x64_pe_entry_wrapper",
            confidence: CrtConfidence::WeakDiagnostic,
            call_target_rva: Some(call_target),
            jmp_target_rva: Some(jmp_target),
            rejection: Some("candidate_not_in_executable_range"),
        }));
    }

    // B7.2: call/jmp target bodies must be present in the scanned text slice.
    // Executable-range membership alone is not enough — reject out-of-slice targets.
    if target_window(text_bytes, text_rva, call_target, 16).is_none() {
        return Err(Some(CrtCandidate {
            rva: cand_rva,
            rule: "msvc_x64_pe_entry_wrapper",
            confidence: CrtConfidence::WeakDiagnostic,
            call_target_rva: Some(call_target),
            jmp_target_rva: Some(jmp_target),
            rejection: Some("call_target_body_out_of_text_slice"),
        }));
    }
    if target_window(text_bytes, text_rva, jmp_target, 16).is_none() {
        return Err(Some(CrtCandidate {
            rva: cand_rva,
            rule: "msvc_x64_pe_entry_wrapper",
            confidence: CrtConfidence::WeakDiagnostic,
            call_target_rva: Some(call_target),
            jmp_target_rva: Some(jmp_target),
            rejection: Some("jmp_target_body_out_of_text_slice"),
        }));
    }

    // B7: semantic target checks when bodies fall inside the scanned text slice.
    // Reject known-wrong S3.10 pair (call common_main / jmp TLS helper) and
    // any call→common_main or jmp→TLS-helper miswire.
    if let Some(reason) =
        semantic_reject_wrapper_targets(text_bytes, text_rva, call_target, jmp_target)
    {
        return Err(Some(CrtCandidate {
            rva: cand_rva,
            rule: "msvc_x64_pe_entry_wrapper",
            confidence: CrtConfidence::WeakDiagnostic,
            call_target_rva: Some(call_target),
            jmp_target_rva: Some(jmp_target),
            rejection: Some(reason),
        }));
    }

    Ok(CrtCandidate {
        rva: cand_rva,
        rule: "msvc_x64_pe_entry_wrapper",
        confidence: CrtConfidence::Strong,
        call_target_rva: Some(call_target),
        jmp_target_rva: Some(jmp_target),
        rejection: None,
    })
}

/// Fail-closed semantic checks for wrapper call/jmp when target bytes are present.
///
/// Uses the **same** packer classifiers as `mida_packers_themida` (no local
/// pseudo-rules). Correct wiring: call → `__security_init_cookie`, jmp →
/// `__scrt_common_main_seh`. Old wrong B6 pair (call common_main / jmp TLS) is rejected.
///
/// B7.2.1: full semantic windows are required (`0x40` jmp / call, `0xC0` call for
/// sentinel). Truncated bodies must not soft-pass by skipping checks.
fn semantic_reject_wrapper_targets(
    text_bytes: &[u8],
    text_rva: u32,
    call_target: u32,
    jmp_target: u32,
) -> Option<&'static str> {
    use mida_packers_themida::{
        is_scrt_common_main_seh_bytes, is_tls_or_dynamic_init_helper_bytes,
        window_contains_security_cookie_sentinel,
    };

    let call_win = target_window(text_bytes, text_rva, call_target, 0x40);
    let jmp_win = target_window(text_bytes, text_rva, jmp_target, 0x40);

    let Some(jmp_w) = jmp_win else {
        return Some("jmp_target_body_out_of_text_slice");
    };
    if is_tls_or_dynamic_init_helper_bytes(jmp_w) {
        return Some("jmp_target_is_tls_or_dynamic_init_helper");
    }
    if !is_scrt_common_main_seh_bytes(jmp_w) {
        return Some("jmp_target_not_scrt_common_main_seh");
    }

    let Some(call_w) = call_win else {
        return Some("call_target_body_out_of_text_slice");
    };
    if is_scrt_common_main_seh_bytes(call_w) {
        return Some("call_target_is_scrt_common_main_seh");
    }
    if is_tls_or_dynamic_init_helper_bytes(call_w) {
        return Some("call_target_is_tls_or_dynamic_init_helper");
    }
    // Cookie-init windows are larger than 0x40 (sentinel may sit past prologue).
    let Some(call_wide) = target_window(text_bytes, text_rva, call_target, 0xC0) else {
        return Some("call_target_body_out_of_text_slice");
    };
    if !window_contains_security_cookie_sentinel(call_wide) {
        return Some("call_target_missing_security_cookie_sentinel");
    }

    None
}

/// Exact-length window into `text_bytes` for a target RVA (B7.2.1 fail-closed).
///
/// Returns `Some` only when the full `[off, off+len)` slice is present.
/// Truncated call bodies (e.g. sentinel-only tail) or truncated jmp prologues
/// must not satisfy semantic checks via a partial window.
fn target_window<'a>(
    text_bytes: &'a [u8],
    text_rva: u32,
    target_rva: u32,
    len: usize,
) -> Option<&'a [u8]> {
    if target_rva < text_rva {
        return None;
    }
    let off = (target_rva - text_rva) as usize;
    let end = off.checked_add(len)?;
    text_bytes.get(off..end)
}

fn checked_rel32_target(next_ip_rva: u32, rel: i32) -> Option<u32> {
    let base = i64::from(next_ip_rva);
    let t = base.checked_add(i64::from(rel))?;
    if t < 0 || t > i64::from(u32::MAX) {
        return None;
    }
    Some(t as u32)
}

fn rva_in_any(rva: u32, ranges: &[ExecutableRange]) -> bool {
    ranges.iter().any(|r| r.contains(rva))
}

fn is_reasonable_function_boundary(text_bytes: &[u8], off: usize) -> bool {
    if off == 0 {
        return true;
    }
    // Require pad / terminator before the candidate — never use "first 4 KiB" as proof.
    matches!(text_bytes[off - 1], 0xCC | 0x90 | 0x00 | 0xC3 | 0xC2)
}

/// Record weak patterns for diagnostics; never accepted as final OEP.
fn collect_weak_diagnostics(text_bytes: &[u8], text_rva: u32, rejected: &mut Vec<CrtCandidate>) {
    // Cap diagnostic volume.
    const MAX_WEAK: usize = 32;
    let mut n = 0usize;

    // Bare sub rsp, imm8 in first 4 KiB only (the historic fail-open trap).
    let bare_end = 0x1000.min(text_bytes.len()).saturating_sub(4);
    for off in 0..bare_end {
        if n >= MAX_WEAK {
            break;
        }
        if text_bytes[off] == 0x48
            && text_bytes[off + 1] == 0x83
            && text_bytes[off + 2] == 0xEC
            && text_bytes[off + 3] <= 0x80
        {
            // Skip if this is the start of a full strong wrapper (already handled).
            if off + WRAPPER_LEN <= text_bytes.len()
                && text_bytes[off + 3] == 0x28
                && text_bytes[off + 4] == 0xE8
                && text_bytes[off + 9] == 0x48
                && text_bytes[off + 10] == 0x83
                && text_bytes[off + 11] == 0xC4
                && text_bytes[off + 12] == 0x28
                && text_bytes[off + 13] == 0xE9
            {
                continue;
            }
            let rva = text_rva.wrapping_add(off as u32);
            rejected.push(CrtCandidate {
                rva,
                rule: "bare_sub_rsp_imm8",
                confidence: CrtConfidence::WeakDiagnostic,
                call_target_rva: None,
                jmp_target_rva: None,
                rejection: Some("bare_sub_rsp_never_accepted_as_pe_entry"),
            });
            n += 1;
        }
    }

    // SEH body: sub rsp,xx ; mov [rsp+20h], 0FFFFFFFE — body only, not PE wrapper.
    let seh_end = text_bytes.len().saturating_sub(13);
    let seh_scan = seh_end.min(0x40_000);
    for off in 0..seh_scan {
        if n >= MAX_WEAK {
            break;
        }
        if text_bytes[off] == 0x48
            && text_bytes[off + 1] == 0x83
            && text_bytes[off + 2] == 0xEC
            && text_bytes[off + 4] == 0x48
            && text_bytes[off + 5] == 0xC7
            && text_bytes[off + 6] == 0x44
            && text_bytes[off + 7] == 0x24
            && text_bytes[off + 8] == 0x20
            && text_bytes[off + 9] == 0xFE
            && text_bytes[off + 10] == 0xFF
            && text_bytes[off + 11] == 0xFF
            && text_bytes[off + 12] == 0xFF
        {
            let rva = text_rva.wrapping_add(off as u32);
            rejected.push(CrtCandidate {
                rva,
                rule: "scrt_common_main_seh_body",
                confidence: CrtConfidence::WeakDiagnostic,
                call_target_rva: None,
                jmp_target_rva: None,
                rejection: Some("seh_body_without_wrapper_never_accepted_as_pe_entry"),
            });
            n += 1;
        }
    }

    // Global-initializer-like: sub rsp,28; mov ecx,imm32; call — not PE entry wrapper.
    let gi_end = 0x2000.min(text_bytes.len()).saturating_sub(12);
    for off in 0..gi_end {
        if n >= MAX_WEAK {
            break;
        }
        if text_bytes[off] == 0x48
            && text_bytes[off + 1] == 0x83
            && text_bytes[off + 2] == 0xEC
            && text_bytes[off + 3] == 0x28
            && text_bytes[off + 4] == 0xB9
        {
            let rva = text_rva.wrapping_add(off as u32);
            rejected.push(CrtCandidate {
                rva,
                rule: "global_initializer_shape",
                confidence: CrtConfidence::WeakDiagnostic,
                call_target_rva: None,
                jmp_target_rva: None,
                rejection: Some("global_initializer_shape_never_accepted_as_pe_entry"),
            });
            n += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Live memory path
// ---------------------------------------------------------------------------

/// Scan decrypted `.text` in live memory for a unique strong CRT PE-entry wrapper.
///
/// Returns:
/// - `Ok(Some(va))` — unique strong wrapper accepted
/// - `Ok(None)` — not found / ambiguous / short read / no executable section
///   (`--oep=crt` must treat `None` as hard error via [`resolve_oep_va`])
pub(super) fn scan_live_memory_for_real_oep(
    dbg: &ProcessSession,
    image_base: usize,
    sections: &[PeSection],
    base_of_data: u64,
    _major_linker_version: u8,
    captured_oep: Option<usize>,
) -> Result<Option<usize>, anyhow::Error> {
    let Some(text_sec) = sections
        .iter()
        .find(|sec| sec.virtual_size > 0x1000 && (sec.characteristics & 0x20000000 != 0))
    else {
        warn!("CRT OEP scan: no suitable executable .text section");
        return Ok(None);
    };

    let text_rva = text_sec.virtual_address;
    let text_base_va = match image_base.checked_add(text_rva as usize) {
        Some(v) => v,
        None => {
            warn!("CRT OEP scan: text_base_va overflow");
            return Ok(None);
        }
    };

    // Prefer full virtual size; optional BaseOfData clamp only when it expands nothing harmful.
    let mut text_len = text_sec.virtual_size as usize;
    if base_of_data != 0 {
        let bod = base_of_data as u32;
        if bod > text_rva {
            let capped = (bod - text_rva) as usize;
            // Never shrink below virtual_size when bod is smaller (legacy PE32); only
            // use bod when it is a larger exclusive end within MAX.
            if capped > text_len {
                text_len = capped;
            }
        }
    }
    if text_len < WRAPPER_LEN {
        warn!("CRT OEP scan: .text too small");
        return Ok(None);
    }
    if text_len > MAX_TEXT_READ {
        info!(
            text_len,
            max = MAX_TEXT_READ,
            "CRT OEP scan: clamping .text read to MAX_TEXT_READ"
        );
        text_len = MAX_TEXT_READ;
    }

    let text_buf = match read_executable_text_chunked(dbg, text_base_va, text_len) {
        Ok(buf) => buf,
        Err(e) => {
            warn!("CRT OEP scan short/failed read (fail-closed): {e}");
            return Ok(None);
        }
    };

    let exec_ranges = executable_ranges_from_sections(sections);
    let captured_rva = captured_oep.and_then(|va| {
        let base = image_base as u64;
        let va = va as u64;
        if va >= base {
            u32::try_from(va - base).ok()
        } else {
            None
        }
    });

    // Ensure captured neighborhood is present when within .text mapping.
    // (Full-section read already covers RVA 0x165F6C for typical images.)
    if let Some(cap) = captured_rva {
        if cap >= text_rva {
            let off = (cap - text_rva) as usize;
            if off >= text_buf.len() {
                warn!(
                    captured_rva = format_args!("{cap:#x}"),
                    text_buf_len = text_buf.len(),
                    "CRT OEP scan: captured_rva beyond read buffer (fail-closed)"
                );
                return Ok(None);
            }
        }
    }

    let result = scan_crt_entry_candidate(&text_buf, text_rva, captured_rva, &exec_ranges);
    log_scan_result(&result, image_base);

    match result {
        ScanCrtResult::Accepted(c) => {
            let va = image_base.wrapping_add(c.rva as usize);
            info!(
                candidate_rva = format_args!("{:#x}", c.rva),
                candidate_va = format_args!("{va:#x}"),
                rule = c.rule,
                confidence = ?c.confidence,
                call_target = c
                    .call_target_rva
                    .map(|t| format!("{t:#x}"))
                    .unwrap_or_else(|| "n/a".into()),
                jmp_target = c
                    .jmp_target_rva
                    .map(|t| format!("{t:#x}"))
                    .unwrap_or_else(|| "n/a".into()),
                "CRT OEP scan ACCEPTED unique strong PE-entry wrapper candidate \
                 (captured/synthesized wrapper — not a claim of absolute true OEP)"
            );
            Ok(Some(va))
        }
        ScanCrtResult::Ambiguous { candidates, .. } => {
            for c in &candidates {
                info!(
                    candidate_rva = format_args!("{:#x}", c.rva),
                    rule = c.rule,
                    "CRT OEP scan AMBIGUOUS strong candidate"
                );
            }
            warn!("CRT OEP scan: multiple strong wrappers — fail-closed (no first-match)");
            Ok(None)
        }
        ScanCrtResult::NotFound { rejected } => {
            for c in rejected.iter().take(16) {
                info!(
                    candidate_rva = format_args!("{:#x}", c.rva),
                    rule = c.rule,
                    rejection = c.rejection.unwrap_or("n/a"),
                    "CRT OEP scan rejected/diagnostic"
                );
            }
            info!("CRT OEP scan: no unique strong PE-entry wrapper");
            Ok(None)
        }
    }
}

fn executable_ranges_from_sections(sections: &[PeSection]) -> Vec<ExecutableRange> {
    sections
        .iter()
        .filter(|s| s.characteristics & 0x20000000 != 0 && s.virtual_size > 0)
        .map(|s| {
            let start = s.virtual_address;
            let end = s.virtual_address.saturating_add(s.virtual_size);
            ExecutableRange {
                rva_start: start,
                rva_end: end,
            }
        })
        .collect()
}

/// Read `total_len` bytes from `base_va` in sequential chunks into one buffer.
///
/// Chunks are assembled contiguously (full image view), so instruction patterns
/// never straddle unread gaps. `CHUNK_OVERLAP` is reserved for alternate
/// per-chunk scan modes; the assembled buffer is the source of truth for the
/// pure scanner. Short read → error (fail-closed).
fn read_executable_text_chunked(
    dbg: &ProcessSession,
    base_va: usize,
    total_len: usize,
) -> Result<Vec<u8>, anyhow::Error> {
    if total_len == 0 {
        return Err(anyhow::anyhow!("zero-length text read"));
    }
    let _overlap = CHUNK_OVERLAP; // documented contract; full-buffer assembly needs none
    let mut out = vec![0u8; total_len];
    let mut pos = 0usize;
    while pos < total_len {
        let want = (total_len - pos).min(READ_CHUNK);
        let read_va = base_va
            .checked_add(pos)
            .ok_or_else(|| anyhow::anyhow!("read_va overflow at pos {pos:#x}"))?;
        let mut chunk = vec![0u8; want];
        let n = dbg
            .read_memory(read_va, &mut chunk)
            .map_err(|e| anyhow::anyhow!("read .text at va={read_va:#x}: {e}"))?;
        if n < want {
            return Err(anyhow::anyhow!(
                "short read at va={read_va:#x}: got {n:#x} want {want:#x} (fail-closed)"
            ));
        }
        out[pos..pos + want].copy_from_slice(&chunk[..want]);
        pos = pos
            .checked_add(want)
            .ok_or_else(|| anyhow::anyhow!("pos overflow after read at {read_va:#x}"))?;
    }
    Ok(out)
}

fn log_scan_result(result: &ScanCrtResult, _image_base: usize) {
    match result {
        ScanCrtResult::Accepted(c) => {
            info!(
                decision = "accepted",
                rva = format_args!("{:#x}", c.rva),
                rule = c.rule,
                confidence = ?c.confidence,
                "CRT OEP final decision"
            );
        }
        ScanCrtResult::Ambiguous { candidates, .. } => {
            info!(
                decision = "ambiguous",
                count = candidates.len(),
                "CRT OEP final decision"
            );
        }
        ScanCrtResult::NotFound { rejected } => {
            info!(
                decision = "not_found",
                rejected = rejected.len(),
                "CRT OEP final decision"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn range_text(end: u32) -> Vec<ExecutableRange> {
        vec![ExecutableRange {
            rva_start: 0x1000,
            rva_end: end,
        }]
    }

    /// Encode strong wrapper with given call/jmp absolute RVAs.
    fn encode_wrapper(cand_rva: u32, call_tgt: u32, jmp_tgt: u32) -> [u8; WRAPPER_LEN] {
        let mut b = [0u8; WRAPPER_LEN];
        b[0] = 0x48;
        b[1] = 0x83;
        b[2] = 0xEC;
        b[3] = 0x28;
        b[4] = 0xE8;
        let call_rel = (call_tgt as i64 - (cand_rva as i64 + 9)) as i32;
        b[5..9].copy_from_slice(&call_rel.to_le_bytes());
        b[9] = 0x48;
        b[10] = 0x83;
        b[11] = 0xC4;
        b[12] = 0x28;
        b[13] = 0xE9;
        let jmp_rel = (jmp_tgt as i64 - (cand_rva as i64 + 18)) as i32;
        b[14..18].copy_from_slice(&jmp_rel.to_le_bytes());
        b
    }

    /// Plant real B6 common-main prologue (shared classifier shape).
    fn plant_common_main(buf: &mut [u8], text_rva: u32, rva: u32) {
        let off = (rva - text_rva) as usize;
        // Real B6 0x165DF8 prefix (enough for shared classifier).
        let body: &[u8] = &[
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0xB9, 0x01, 0x00, 0x00,
            0x00, 0xE8, 0x00, 0x00, 0x00, 0x00,
        ];
        buf[off..off + body.len()].copy_from_slice(body);
    }

    /// Minimal `__security_init_cookie` body with DEFAULT sentinel imm64.
    fn plant_security_init_cookie(buf: &mut [u8], text_rva: u32, rva: u32) {
        let off = (rva - text_rva) as usize;
        let mut body = vec![
            0x48, 0x83, 0xEC, 0x28, // sub rsp,28
            0x48, 0xB8, // mov rax, imm64
        ];
        body.extend_from_slice(&0x0000_2B99_2DDF_A232u64.to_le_bytes());
        body.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xC3]); // add rsp,28; ret
        buf[off..off + body.len()].copy_from_slice(&body);
    }

    /// Real B6 TLS helper prefix (`cmp edx, 2`).
    fn plant_tls_helper(buf: &mut [u8], text_rva: u32, rva: u32) {
        let off = (rva - text_rva) as usize;
        let body: &[u8] = &[
            0x83, 0xFA, 0x02, 0x75, 0x60, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC,
            0x20, 0xC3,
        ];
        buf[off..off + body.len()].copy_from_slice(body);
    }

    fn plant_valid_targets(buf: &mut [u8], text_rva: u32, call_tgt: u32, jmp_tgt: u32) {
        plant_security_init_cookie(buf, text_rva, call_tgt);
        plant_common_main(buf, text_rva, jmp_tgt);
    }

    /// Load real B6 CRT text/data slices (source SHA 2DDDAF17…D2871).
    fn real_b6_text_slice() -> (Vec<u8>, u32) {
        // Shared offline extract from B6 PE (same bins as packer fixtures).
        let bytes =
            include_bytes!("../../../packers/themida/src/oep/fixtures/text_crt_165000_166300.bin");
        (bytes.to_vec(), 0x165000u32)
    }

    /// S3.10.10 static bytes at RVA 0x10F0 (global initializer / helper — not PE CRT wrapper).
    const S310_RVA_10F0: &[u8] = &[
        0x48, 0x83, 0xEC, 0x28, 0xB9, 0x20, 0x00, 0x00, 0x00, 0xE8, 0x06, 0x3F, 0x16, 0x00, 0x48,
        0x8D, 0x0D, 0x3B, 0x16, 0x1A, 0x00, 0x48, 0x89, 0x00, 0x48, 0x89, 0x40, 0x08, 0x48, 0x89,
        0x40, 0x10, 0x66, 0xC7, 0x40, 0x18, 0x01, 0x01, 0x48, 0x89, 0x05, 0x63, 0x8A, 0x1F, 0x00,
        0x48, 0x83, 0xC4, 0x28, 0xE9, 0x52, 0x41, 0x16, 0x00,
    ];

    /// Historical wrong S3.10 wrapper at 0x165F6C: call 0x165DF8 / jmp 0x165290.
    const S310_WRONG_WRAPPER_165F6C: &[u8] = &[
        0x48, 0x83, 0xEC, 0x28, 0xE8, 0x83, 0xFE, 0xFF, 0xFF, 0x48, 0x83, 0xC4, 0x28, 0xE9, 0x12,
        0xF3, 0xFF, 0xFF,
    ];

    const S310_WRAPPER_RVA: u32 = 0x165F6C;
    const S310_COOKIE_FN: u32 = 0x1661F0;
    const S310_COMMON_MAIN: u32 = 0x165DF8;
    const S310_TLS_HELPER: u32 = 0x165290;

    #[test]
    fn bare_sub_rsp_at_0x10f0_rejected() {
        // Only first 4 bytes of a bare sub rsp — no full wrapper.
        let mut buf = vec![0xCCu8; 0x200];
        let off = 0xF0; // text_rva 0x1000 → rva 0x10F0
        buf[off] = 0x48;
        buf[off + 1] = 0x83;
        buf[off + 2] = 0xEC;
        buf[off + 3] = 0x28;
        let r = scan_crt_entry_candidate(&buf, 0x1000, None, &range_text(0x3000));
        assert!(
            r.accepted_rva().is_none(),
            "bare sub rsp must not be accepted"
        );
        match r {
            ScanCrtResult::NotFound { rejected } => {
                assert!(
                    rejected.iter().any(|c| c.rva == 0x10F0
                        && c.rule == "bare_sub_rsp_imm8"
                        && c.rejection.is_some()),
                    "expected bare_sub_rsp diagnostic for 0x10F0, got {rejected:?}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn global_initializer_shape_rejected() {
        let mut buf = vec![0xCCu8; 0x200];
        let off = 0xF0;
        buf[off..off + S310_RVA_10F0.len()].copy_from_slice(S310_RVA_10F0);
        let r = scan_crt_entry_candidate(&buf, 0x1000, None, &range_text(0x200000));
        assert_ne!(r.accepted_rva(), Some(0x10F0));
        assert!(r.accepted_rva().is_none() || r.accepted_rva() != Some(0x10F0));
        match &r {
            ScanCrtResult::NotFound { rejected } | ScanCrtResult::Ambiguous { rejected, .. } => {
                assert!(
                    rejected.iter().any(|c| {
                        c.rva == 0x10F0
                            && (c.rule == "global_initializer_shape"
                                || c.rule == "bare_sub_rsp_imm8")
                    }),
                    "0x10F0 must be rejected as weak diagnostic: {rejected:?}"
                );
            }
            ScanCrtResult::Accepted(c) => {
                panic!("must not accept global initializer: {c:?}");
            }
        }
    }

    #[test]
    fn real_b6_old_wrapper_rejected() {
        // Real B6 CRT text slice + historical wrong wrapper at 0x165F6C.
        let (mut buf, text_rva) = real_b6_text_slice();
        let off = (S310_WRAPPER_RVA - text_rva) as usize;
        buf[off..off + WRAPPER_LEN].copy_from_slice(S310_WRONG_WRAPPER_165F6C);
        let ranges = range_text(0x1B0000);
        let r = scan_crt_entry_candidate(&buf, text_rva, Some(S310_WRAPPER_RVA), &ranges);
        assert!(
            r.accepted_rva().is_none(),
            "old wrong call=0x165DF8 jmp=0x165290 must be rejected"
        );
        match r {
            ScanCrtResult::NotFound { rejected } | ScanCrtResult::Ambiguous { rejected, .. } => {
                assert!(
                    rejected.iter().any(|c| {
                        c.rva == S310_WRAPPER_RVA
                            && (c.rejection == Some("jmp_target_is_tls_or_dynamic_init_helper")
                                || c.rejection == Some("call_target_is_scrt_common_main_seh")
                                || c.rejection
                                    == Some("call_target_missing_security_cookie_sentinel")
                                || c.rejection == Some("jmp_target_not_scrt_common_main_seh"))
                    }),
                    "expected semantic reject of old targets, got {rejected:?}"
                );
            }
            ScanCrtResult::Accepted(c) => panic!("must not accept old wrong wrapper: {c:?}"),
        }
    }

    #[test]
    fn real_b6_corrected_wrapper_accepted_by_cli_scanner() {
        // Real B6 bodies at 0x1661F0 / 0x165DF8; corrected wrapper at 0x165F6C.
        let (mut buf, text_rva) = real_b6_text_slice();
        let off = (S310_WRAPPER_RVA - text_rva) as usize;
        let w = encode_wrapper(S310_WRAPPER_RVA, S310_COOKIE_FN, S310_COMMON_MAIN);
        buf[off..off + WRAPPER_LEN].copy_from_slice(&w);
        let ranges = range_text(0x1B0000);
        let r = scan_crt_entry_candidate(&buf, text_rva, Some(S310_WRAPPER_RVA), &ranges);
        match r {
            ScanCrtResult::Accepted(c) => {
                assert_eq!(c.rva, S310_WRAPPER_RVA);
                assert_eq!(c.rule, "msvc_x64_pe_entry_wrapper");
                assert_eq!(c.confidence, CrtConfidence::Strong);
                assert_eq!(c.call_target_rva, Some(S310_COOKIE_FN));
                assert_eq!(c.jmp_target_rva, Some(S310_COMMON_MAIN));
            }
            other => panic!("expected Accepted corrected real B6 wrapper, got {other:?}"),
        }
    }

    #[test]
    fn wrapper_beyond_1m_is_scanned() {
        // Historical bug: live path truncated at 0x100000 and missed RVA 0x165F6C.
        let (mut buf, text_rva) = real_b6_text_slice();
        let off = (S310_WRAPPER_RVA - text_rva) as usize;
        assert!(
            (S310_WRAPPER_RVA - 0x1000) > 0x100_000,
            "fixture must sit beyond 1 MiB from image text base"
        );
        let w = encode_wrapper(S310_WRAPPER_RVA, S310_COOKIE_FN, S310_COMMON_MAIN);
        buf[off..off + WRAPPER_LEN].copy_from_slice(&w);
        let r = scan_crt_entry_candidate(
            &buf,
            text_rva,
            Some(S310_WRAPPER_RVA),
            &range_text(0x1B0000),
        );
        assert_eq!(r.accepted_rva(), Some(S310_WRAPPER_RVA));
    }

    #[test]
    fn seh_body_without_wrapper_rejected() {
        // 48 83 EC 28  48 C7 44 24 20 FE FF FF FF
        let mut buf = vec![0xCCu8; 0x2000];
        let off = 0x1500;
        let seh: &[u8] = &[
            0x48, 0x83, 0xEC, 0x28, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE, 0xFF, 0xFF, 0xFF, 0xC3,
        ];
        buf[off..off + seh.len()].copy_from_slice(seh);
        let r = scan_crt_entry_candidate(&buf, 0x1000, None, &range_text(0x5000));
        assert!(r.accepted_rva().is_none());
        match r {
            ScanCrtResult::NotFound { rejected } => {
                assert!(rejected
                    .iter()
                    .any(|c| c.rule == "scrt_common_main_seh_body"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn invalid_call_target_rejected() {
        let cand = 0x2000u32;
        // call target outside executable range but within signed rel32 distance
        let w = encode_wrapper(cand, 0x5000, 0x2100);
        let mut buf = vec![0xCCu8; 0x200];
        let off = (cand - 0x1000) as usize;
        buf.resize(off + WRAPPER_LEN + 8, 0xCC);
        buf[off..off + WRAPPER_LEN].copy_from_slice(&w);
        let r = scan_crt_entry_candidate(&buf, 0x1000, None, &range_text(0x4000));
        assert!(r.accepted_rva().is_none());
        match r {
            ScanCrtResult::NotFound { rejected } => {
                assert!(
                    rejected.iter().any(|c| {
                        c.rva == cand && c.rejection == Some("invalid_call_target_not_executable")
                    }),
                    "rejected={rejected:?}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn invalid_jmp_target_rejected() {
        let cand = 0x2000u32;
        let w = encode_wrapper(cand, 0x2100, 0x5000);
        let mut buf = vec![0xCCu8; 0x200];
        let off = (cand - 0x1000) as usize;
        buf.resize(off + WRAPPER_LEN + 8, 0xCC);
        buf[off..off + WRAPPER_LEN].copy_from_slice(&w);
        let r = scan_crt_entry_candidate(&buf, 0x1000, None, &range_text(0x4000));
        assert!(r.accepted_rva().is_none());
        match r {
            ScanCrtResult::NotFound { rejected } => {
                assert!(
                    rejected.iter().any(|c| {
                        c.rva == cand && c.rejection == Some("invalid_jmp_target_not_executable")
                    }),
                    "rejected={rejected:?}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn target_body_out_of_slice_rejected() {
        let text_rva = 0x1000u32;
        let cand = 0x1100u32;
        let call_target = 0x3000u32;
        let jmp_target = 0x3100u32;
        let mut buf = vec![0xCCu8; 0x400];
        let off = (cand - text_rva) as usize;
        let wrapper = encode_wrapper(cand, call_target, jmp_target);
        buf[off..off + WRAPPER_LEN].copy_from_slice(&wrapper);

        // Executable-range membership is insufficient when target bodies are
        // absent from the exact text slice consumed by the CLI scanner.
        let result = scan_crt_entry_candidate(&buf, text_rva, Some(cand), &range_text(0x4000));
        assert!(result.accepted_rva().is_none());
        match result {
            ScanCrtResult::NotFound { rejected } | ScanCrtResult::Ambiguous { rejected, .. } => {
                assert!(rejected.iter().any(|c| {
                    c.rva == cand && c.rejection == Some("call_target_body_out_of_text_slice")
                }))
            }
            ScanCrtResult::Accepted(candidate) => {
                panic!("out-of-slice target body must be rejected: {candidate:?}")
            }
        }
    }

    #[test]
    fn truncated_wrapper_rejected() {
        // Only 12 bytes of wrapper — incomplete instruction stream.
        let mut buf = vec![0xCCu8; 32];
        buf[0..12].copy_from_slice(&[
            0x48, 0x83, 0xEC, 0x28, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4,
        ]);
        let r = scan_crt_entry_candidate(&buf, 0x1000, None, &range_text(0x3000));
        assert!(r.accepted_rva().is_none());
    }

    #[test]
    fn two_strong_candidates_ambiguous() {
        let mut buf = vec![0xCCu8; 0x4000];
        let c1 = 0x2000u32;
        let c2 = 0x3000u32;
        let w1 = encode_wrapper(c1, 0x2100, 0x2200);
        let w2 = encode_wrapper(c2, 0x3100, 0x3200);
        let o1 = (c1 - 0x1000) as usize;
        let o2 = (c2 - 0x1000) as usize;
        buf[o1..o1 + WRAPPER_LEN].copy_from_slice(&w1);
        buf[o2..o2 + WRAPPER_LEN].copy_from_slice(&w2);
        plant_valid_targets(&mut buf, 0x1000, 0x2100, 0x2200);
        plant_valid_targets(&mut buf, 0x1000, 0x3100, 0x3200);
        let r = scan_crt_entry_candidate(&buf, 0x1000, None, &range_text(0x5000));
        match r {
            ScanCrtResult::Ambiguous { candidates, .. } => {
                assert_eq!(candidates.len(), 2);
                let rvas: Vec<u32> = candidates.iter().map(|c| c.rva).collect();
                assert!(rvas.contains(&c1) && rvas.contains(&c2));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn crt_policy_no_candidate_fails_closed() {
        let err = resolve_oep_va(OepPolicy::Crt, 0x140000000, 0x140165F6C, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("fail-closed") || msg.contains("--oep=crt"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn captured_policy_ignores_scanner_none() {
        let va = resolve_oep_va(OepPolicy::Captured, 0x140000000, 0x140165F6C, None).unwrap();
        assert_eq!(va, 0x140165F6C);
    }

    #[test]
    fn fixed_policy_unchanged() {
        let va = resolve_oep_va(OepPolicy::Fixed(0x10F0), 0x140000000, 0x140165F6C, None).unwrap();
        assert_eq!(va, 0x1400010F0);
        let va2 = resolve_oep_va(
            OepPolicy::Fixed(0x10F0),
            0x140000000,
            0x140165F6C,
            Some(0x99),
        )
        .unwrap();
        assert_eq!(va2, 0x1400010F0);
    }

    #[test]
    fn s310_static_0x10f0_never_accepted_as_crt_oep() {
        // Global-initializer shape at 0x10F0 must never win over corrected wrapper.
        let mut buf = vec![0xCCu8; 0x200];
        let off_10f0 = 0xF0usize;
        buf[off_10f0..off_10f0 + S310_RVA_10F0.len()].copy_from_slice(S310_RVA_10F0);
        let (mut crt, text_rva) = real_b6_text_slice();
        let off_w = (S310_WRAPPER_RVA - text_rva) as usize;
        let w = encode_wrapper(S310_WRAPPER_RVA, S310_COOKIE_FN, S310_COMMON_MAIN);
        crt[off_w..off_w + WRAPPER_LEN].copy_from_slice(&w);
        // Scan only CRT slice (0x10F0 not present) — corrected wrapper accepted.
        let r = scan_crt_entry_candidate(
            &crt,
            text_rva,
            Some(S310_WRAPPER_RVA),
            &range_text(0x1B0000),
        );
        assert_eq!(r.accepted_rva(), Some(S310_WRAPPER_RVA));
        // Bare 0x10F0 buffer never accepted.
        let r2 = scan_crt_entry_candidate(&buf, 0x1000, None, &range_text(0x200000));
        assert_ne!(r2.accepted_rva(), Some(0x10F0));
    }

    #[test]
    fn crt_policy_accepts_scanned_va() {
        let va =
            resolve_oep_va(OepPolicy::Crt, 0x140000000, 0x140165F6C, Some(0x140165F6C)).unwrap();
        assert_eq!(va, 0x140165F6C);
    }

    #[test]
    fn captured_near_disambiguates_two_strong() {
        let mut buf = vec![0xCCu8; 0x4000];
        let c1 = 0x2000u32;
        let c2 = 0x3000u32;
        let w1 = encode_wrapper(c1, 0x2100, 0x2200);
        let w2 = encode_wrapper(c2, 0x3100, 0x3200);
        buf[(c1 - 0x1000) as usize..][..WRAPPER_LEN].copy_from_slice(&w1);
        buf[(c2 - 0x1000) as usize..][..WRAPPER_LEN].copy_from_slice(&w2);
        plant_valid_targets(&mut buf, 0x1000, 0x2100, 0x2200);
        plant_valid_targets(&mut buf, 0x1000, 0x3100, 0x3200);
        let r = scan_crt_entry_candidate(&buf, 0x1000, Some(c2), &range_text(0x5000));
        assert_eq!(r.accepted_rva(), Some(c2));
    }

    // -----------------------------------------------------------------------
    // B7.2.1 — exact-length target windows (no truncated semantic body)
    // -----------------------------------------------------------------------

    #[test]
    fn truncated_call_body_with_sentinel_rejected() {
        // call target at end of text slice: only DEFAULT sentinel imm64 (8 bytes),
        // not a full 0x40 / 0xC0 semantic window.
        let text_rva = 0x1000u32;
        let cand = 0x1100u32;
        let jmp_target = 0x1150u32;
        // call_target + 8 == end of buffer
        let call_target = 0x1300u32;
        let call_off = (call_target - text_rva) as usize;
        let mut buf = vec![0xCCu8; call_off + 8];
        let off = (cand - text_rva) as usize;
        let wrapper = encode_wrapper(cand, call_target, jmp_target);
        buf[off..off + WRAPPER_LEN].copy_from_slice(&wrapper);
        assert_eq!(buf.len() - call_off, 8);
        buf[call_off..call_off + 8].copy_from_slice(&0x0000_2B99_2DDF_A232u64.to_le_bytes());
        // jmp body needs room — place jmp earlier with full plant space by resizing first
        // (plant_common_main writes ~20 bytes at 0x1150 → off 0x150; buffer is large enough)
        plant_common_main(&mut buf, text_rva, jmp_target);

        let result = scan_crt_entry_candidate(&buf, text_rva, Some(cand), &range_text(0x4000));
        assert!(result.accepted_rva().is_none());
        match result {
            ScanCrtResult::NotFound { rejected } | ScanCrtResult::Ambiguous { rejected, .. } => {
                assert!(
                    rejected.iter().any(|c| {
                        c.rva == cand && c.rejection == Some("call_target_body_out_of_text_slice")
                    }),
                    "truncated call body with only sentinel must be rejected: {rejected:?}"
                );
            }
            ScanCrtResult::Accepted(c) => {
                panic!("truncated call body must not be accepted: {c:?}")
            }
        }
    }

    #[test]
    fn truncated_jmp_body_with_valid_prefix_rejected() {
        // jmp target has only a short common-main prefix — not a full 0x40 window.
        let text_rva = 0x1000u32;
        let cand = 0x1100u32;
        let call_target = 0x1200u32;
        // Only 16 bytes available at jmp_target (prologue only).
        let jmp_target = 0x1400u32;
        let jmp_off = (jmp_target - text_rva) as usize;
        let mut buf = vec![0xCCu8; jmp_off + 16];
        let off = (cand - text_rva) as usize;
        let wrapper = encode_wrapper(cand, call_target, jmp_target);
        buf[off..off + WRAPPER_LEN].copy_from_slice(&wrapper);
        plant_security_init_cookie(&mut buf, text_rva, call_target);
        assert_eq!(buf.len() - jmp_off, 16);
        let prefix: &[u8] = &[
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0xB9, 0x01, 0x00, 0x00,
            0x00, 0xE8,
        ];
        buf[jmp_off..jmp_off + prefix.len()].copy_from_slice(prefix);

        let result = scan_crt_entry_candidate(&buf, text_rva, Some(cand), &range_text(0x4000));
        assert!(result.accepted_rva().is_none());
        match result {
            ScanCrtResult::NotFound { rejected } | ScanCrtResult::Ambiguous { rejected, .. } => {
                assert!(
                    rejected.iter().any(|c| {
                        c.rva == cand && c.rejection == Some("jmp_target_body_out_of_text_slice")
                    }),
                    "truncated jmp body with valid prefix must be rejected: {rejected:?}"
                );
            }
            ScanCrtResult::Accepted(c) => {
                panic!("truncated jmp body must not be accepted: {c:?}")
            }
        }
    }

    #[test]
    fn target_window_requires_exact_length() {
        let buf = vec![0u8; 32];
        // off=24, len=16 → end=40 > 32 → None
        assert!(target_window(&buf, 0x1000, 0x1018, 16).is_none());
        // off=16, len=16 → full slice
        assert_eq!(
            target_window(&buf, 0x1000, 0x1010, 16).map(|w| w.len()),
            Some(16)
        );
        // partial min() behavior is forbidden
        assert!(target_window(&buf, 0x1000, 0x1018, 8).is_some());
        assert!(target_window(&buf, 0x1000, 0x1019, 8).is_none());
    }
}
