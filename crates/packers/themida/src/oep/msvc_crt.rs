//! Offline fail-closed MSVC CRT target resolution and PE-entry wrapper synthesis.
//!
//! Correct PE-entry wrapper (18 bytes, Win64 stack-alignment contract):
//! ```text
//!   sub rsp, 28h
//!   call __security_init_cookie
//!   add rsp, 28h
//!   jmp  __scrt_common_main_seh
//! ```
//!
//! Pure offline scanners only — no process launch, no live approval/session.

use tracing::{info, warn};

use mida_core::DebuggerCore;

use crate::error::ThemidaError;

/// MSVC x64 default SecurityCookie sentinel (`__security_init_cookie` regenerates
/// only while storage still equals this value).
pub const DEFAULT_SECURITY_COOKIE: u64 = 0x0000_2B99_2DDF_A232;

/// Strong PE-entry wrapper length.
pub const MSVC_OEP_WRAPPER_LEN: usize = 18;

/// Half-open executable RVA range `[rva_start, rva_end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecRange {
    pub rva_start: u32,
    pub rva_end: u32,
}

impl ExecRange {
    #[must_use]
    pub fn contains(self, rva: u32) -> bool {
        rva >= self.rva_start && rva < self.rva_end
    }
}

/// Cookie + complement RVAs (may be non-adjacent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieComplementSite {
    pub cookie_rva: u32,
    pub complement_rva: u32,
}

/// Minimal PE section view for cookie-storage selection (name-independent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeSectionView {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
}

/// IMAGE_SCN_MEM_EXECUTE
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// IMAGE_SCN_MEM_READ
const SCN_MEM_READ: u32 = 0x4000_0000;
/// IMAGE_SCN_MEM_WRITE
const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Resolved CRT targets for MSVC x64 PE-entry synthesis.
///
/// `cookie_site` is authoritative (xref-derived) and must never be discarded
/// after successful resolve — dump/plant paths consume it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsvcCrtTargets {
    pub security_init_cookie_rva: u32,
    pub scrt_common_main_seh_rva: u32,
    /// Authoritative cookie + complement RVAs from `__security_init_cookie` xrefs.
    pub cookie_site: CookieComplementSite,
}

/// Fail-closed resolution / synthesis errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsvcCrtResolveError {
    MissingSecurityInitCookie,
    AmbiguousSecurityInitCookie(usize),
    MissingCommonMain,
    AmbiguousCommonMain(usize),
    InvalidCookieSite,
    /// Cookie/complement RVAs not in a single R+W non-X section (or bounds fail).
    CookieSectionNotFound,
    TargetNotExecutable {
        rva: u32,
        role: &'static str,
    },
    Rel32Overflow {
        role: &'static str,
    },
    PartialWrite {
        expected: usize,
        actual: usize,
    },
    SemanticReject {
        reason: &'static str,
    },
}

impl std::fmt::Display for MsvcCrtResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSecurityInitCookie => {
                write!(f, "missing unique __security_init_cookie candidate")
            }
            Self::AmbiguousSecurityInitCookie(n) => {
                write!(f, "ambiguous __security_init_cookie ({n} candidates)")
            }
            Self::MissingCommonMain => {
                write!(f, "missing unique __scrt_common_main_seh candidate")
            }
            Self::AmbiguousCommonMain(n) => {
                write!(f, "ambiguous __scrt_common_main_seh ({n} candidates)")
            }
            Self::InvalidCookieSite => write!(f, "invalid or missing cookie/complement site"),
            Self::CookieSectionNotFound => {
                write!(
                    f,
                    "cookie/complement not in a single readable+writable non-executable section"
                )
            }
            Self::TargetNotExecutable { rva, role } => {
                write!(f, "{role} target {rva:#x} not in executable range")
            }
            Self::Rel32Overflow { role } => write!(f, "rel32 overflow encoding {role}"),
            Self::PartialWrite { expected, actual } => {
                write!(f, "partial write of MSVC OEP stub ({actual}/{expected})")
            }
            Self::SemanticReject { reason } => write!(f, "MSVC CRT semantic reject: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Cookie / complement locator (non-adjacent pairs allowed)
// ---------------------------------------------------------------------------

/// Locate a unique SecurityCookie + complement pair in a data slice.
///
/// Cookie and complement need not be adjacent. Pairing rule:
/// - cookie is plausible (non-zero, not all-ones, upper 16 bits clear for MSVC x64)
/// - complement == !cookie
/// - when multiple pairs exist, prefer the DEFAULT sentinel cookie if unique;
///   otherwise require a single unique cookie value (any complement site).
pub fn find_cookie_complement_site(
    data_bytes: &[u8],
    data_rva: u32,
) -> Result<CookieComplementSite, MsvcCrtResolveError> {
    if data_bytes.len() < 16 {
        return Err(MsvcCrtResolveError::InvalidCookieSite);
    }

    // Collect all plausible cookie offsets and complement offsets for each value.
    let mut cookies: Vec<(u32, u64)> = Vec::new(); // (rva, value)
    for off in (0..=data_bytes.len().saturating_sub(8)).step_by(8) {
        let v = u64::from_le_bytes(data_bytes[off..off + 8].try_into().unwrap());
        if is_plausible_cookie(v) {
            cookies.push((data_rva.saturating_add(off as u32), v));
        }
    }

    // For each cookie, find complements (!cookie) elsewhere in the section.
    let mut pairs: Vec<CookieComplementSite> = Vec::new();
    for &(cookie_rva, cookie_val) in &cookies {
        let want = !cookie_val;
        for off in (0..=data_bytes.len().saturating_sub(8)).step_by(8) {
            let comp_rva = data_rva.saturating_add(off as u32);
            if comp_rva == cookie_rva {
                continue;
            }
            let v = u64::from_le_bytes(data_bytes[off..off + 8].try_into().unwrap());
            if v == want {
                pairs.push(CookieComplementSite {
                    cookie_rva,
                    complement_rva: comp_rva,
                });
            }
        }
    }

    if pairs.is_empty() {
        return Err(MsvcCrtResolveError::InvalidCookieSite);
    }

    // Prefer DEFAULT sentinel if it yields a unique cookie_rva.
    let default_pairs: Vec<_> = pairs
        .iter()
        .copied()
        .filter(|p| {
            let off = (p.cookie_rva - data_rva) as usize;
            let v = u64::from_le_bytes(data_bytes[off..off + 8].try_into().unwrap());
            v == DEFAULT_SECURITY_COOKIE
        })
        .collect();
    if default_pairs.len() == 1 {
        return Ok(default_pairs[0]);
    }
    if default_pairs.len() > 1 {
        // Same cookie_rva with multiple complements? take unique cookie_rva.
        let mut rvas: Vec<u32> = default_pairs.iter().map(|p| p.cookie_rva).collect();
        rvas.sort_unstable();
        rvas.dedup();
        if rvas.len() == 1 {
            // Prefer nearest complement after cookie, else first.
            let mut same: Vec<_> = default_pairs
                .into_iter()
                .filter(|p| p.cookie_rva == rvas[0])
                .collect();
            same.sort_by_key(|p| p.complement_rva.abs_diff(p.cookie_rva));
            return Ok(same[0]);
        }
        return Err(MsvcCrtResolveError::InvalidCookieSite);
    }

    // No default: require unique cookie_rva among all pairs.
    let mut cookie_rvas: Vec<u32> = pairs.iter().map(|p| p.cookie_rva).collect();
    cookie_rvas.sort_unstable();
    cookie_rvas.dedup();
    if cookie_rvas.len() != 1 {
        return Err(MsvcCrtResolveError::InvalidCookieSite);
    }
    let cookie_rva = cookie_rvas[0];
    let mut same: Vec<_> = pairs
        .into_iter()
        .filter(|p| p.cookie_rva == cookie_rva)
        .collect();
    same.sort_by_key(|p| p.complement_rva.abs_diff(p.cookie_rva));
    Ok(same[0])
}

fn is_plausible_cookie(value: u64) -> bool {
    value != 0 && value != u64::MAX && value <= 0x0000_ffff_ffff_ffff
}

// ---------------------------------------------------------------------------
// Section-name-independent cookie storage selection
// ---------------------------------------------------------------------------

/// True if `rva` is fully contained in `[va, va+vsize)` for `len` bytes (fail-closed).
#[must_use]
pub fn rva_range_in_section(rva: u32, len: u32, va: u32, vsize: u32) -> bool {
    if vsize == 0 || len == 0 {
        return false;
    }
    let Some(end) = rva.checked_add(len) else {
        return false;
    };
    let Some(sec_end) = va.checked_add(vsize) else {
        return false;
    };
    rva >= va && end <= sec_end
}

/// Select the unique R+W non-executable section that contains both cookie and
/// complement RVAs (8-byte slots). Section **name is ignored**.
///
/// Fail-closed when:
/// - cookie and complement are not in the same section
/// - section is missing READ or WRITE, or has EXECUTE
/// - either 8-byte slot overflows the section
/// - zero or multiple matching sections
pub fn select_cookie_storage_section(
    sections: &[PeSectionView],
    site: CookieComplementSite,
) -> Result<PeSectionView, MsvcCrtResolveError> {
    if site.cookie_rva == site.complement_rva {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "cookie_and_complement_identical",
        });
    }

    let mut matches: Vec<PeSectionView> = Vec::new();
    for s in sections {
        let chars = s.characteristics;
        let readable = chars & SCN_MEM_READ != 0;
        let writable = chars & SCN_MEM_WRITE != 0;
        let executable = chars & SCN_MEM_EXECUTE != 0;
        if !readable || !writable || executable {
            // Structural reject: still check whether either RVA lands here so
            // callers can distinguish "wrong section class" vs "not found".
            let cookie_here =
                rva_range_in_section(site.cookie_rva, 8, s.virtual_address, s.virtual_size);
            let comp_here =
                rva_range_in_section(site.complement_rva, 8, s.virtual_address, s.virtual_size);
            if cookie_here || comp_here {
                if !writable {
                    return Err(MsvcCrtResolveError::SemanticReject {
                        reason: "cookie_section_not_writable",
                    });
                }
                if executable {
                    return Err(MsvcCrtResolveError::SemanticReject {
                        reason: "cookie_section_executable",
                    });
                }
                if !readable {
                    return Err(MsvcCrtResolveError::SemanticReject {
                        reason: "cookie_section_not_readable",
                    });
                }
            }
            continue;
        }
        let cookie_ok = rva_range_in_section(site.cookie_rva, 8, s.virtual_address, s.virtual_size);
        let comp_ok =
            rva_range_in_section(site.complement_rva, 8, s.virtual_address, s.virtual_size);
        if cookie_ok && comp_ok {
            matches.push(*s);
        } else if cookie_ok != comp_ok {
            // Split across sections — fail closed.
            return Err(MsvcCrtResolveError::SemanticReject {
                reason: "cookie_and_complement_not_same_section",
            });
        }
    }

    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(MsvcCrtResolveError::CookieSectionNotFound),
        _ => Err(MsvcCrtResolveError::SemanticReject {
            reason: "ambiguous_cookie_storage_section",
        }),
    }
}

// ---------------------------------------------------------------------------
// __security_init_cookie resolver (pure offline, unique, fail-closed)
// ---------------------------------------------------------------------------

/// Resolve a unique `__security_init_cookie` RVA in executable image bytes.
///
/// Validation (all required):
/// 1. Function contains the DEFAULT sentinel immediate `0x2B992DDFA232`
/// 2. RIP-relative stores resolve to `site.cookie_rva` and (after NOT) `site.complement_rva`
/// 3. Exactly one such function start in `exec_ranges`
pub fn resolve_security_init_cookie(
    text_bytes: &[u8],
    text_rva: u32,
    site: CookieComplementSite,
    exec_ranges: &[ExecRange],
) -> Result<u32, MsvcCrtResolveError> {
    let mut candidates: Vec<u32> = Vec::new();
    for func_rva in iter_security_init_candidates(text_bytes, text_rva, exec_ranges) {
        let func_off = (func_rva - text_rva) as usize;
        let window = &text_bytes[func_off..text_bytes.len().min(func_off + 0x200)];
        if function_writes_cookie_and_complement(
            window,
            func_rva,
            site.cookie_rva,
            site.complement_rva,
        ) && !candidates.contains(&func_rva)
        {
            candidates.push(func_rva);
        }
    }

    match candidates.len() {
        0 => Err(MsvcCrtResolveError::MissingSecurityInitCookie),
        1 => Ok(candidates[0]),
        n => Err(MsvcCrtResolveError::AmbiguousSecurityInitCookie(n)),
    }
}

/// Resolve cookie/complement exclusively via `__security_init_cookie` RIP-rel store xrefs.
///
/// Prefer this over data-section pair scanning when the cookie function body is present.
pub fn resolve_cookie_site_via_security_init_xrefs(
    text_bytes: &[u8],
    text_rva: u32,
    exec_ranges: &[ExecRange],
) -> Result<(u32, CookieComplementSite), MsvcCrtResolveError> {
    let mut found: Vec<(u32, CookieComplementSite)> = Vec::new();
    for func_rva in iter_security_init_candidates(text_bytes, text_rva, exec_ranges) {
        let func_off = (func_rva - text_rva) as usize;
        let window = &text_bytes[func_off..text_bytes.len().min(func_off + 0x200)];
        if let Ok(site) = cookie_complement_from_security_init_xrefs(window, func_rva) {
            if !found.iter().any(|(r, _)| *r == func_rva) {
                found.push((func_rva, site));
            }
        }
    }
    match found.len() {
        0 => Err(MsvcCrtResolveError::MissingSecurityInitCookie),
        1 => Ok(found.into_iter().next().unwrap()),
        n => Err(MsvcCrtResolveError::AmbiguousSecurityInitCookie(n)),
    }
}

fn iter_security_init_candidates(
    text_bytes: &[u8],
    text_rva: u32,
    exec_ranges: &[ExecRange],
) -> Vec<u32> {
    let mut out = Vec::new();
    let scan_end = text_bytes.len().saturating_sub(16);
    let mut i = 0usize;
    while i < scan_end {
        // mov r64, imm64 of DEFAULT sentinel: 48 B8..BF + imm64 (includes 48 BB = mov rbx)
        if text_bytes[i] == 0x48
            && (0xB8..=0xBF).contains(&text_bytes[i + 1])
            && i + 10 <= text_bytes.len()
        {
            let imm = u64::from_le_bytes(text_bytes[i + 2..i + 10].try_into().unwrap());
            if imm == DEFAULT_SECURITY_COOKIE {
                if let Some(func_rva) = find_func_start_near(text_bytes, text_rva, i, exec_ranges) {
                    if !out.contains(&func_rva) {
                        out.push(func_rva);
                    }
                }
            }
        }
        i += 1;
    }
    out
}

fn find_func_start_near(
    text_bytes: &[u8],
    text_rva: u32,
    imm_off: usize,
    exec_ranges: &[ExecRange],
) -> Option<u32> {
    // Prefer INT3/NOP/ret padding boundary; else accept aligned offset of imm itself
    // only when at section start-ish (imm_off small).
    let back = imm_off.min(0x80);
    for delta in 0..=back {
        let off = imm_off - delta;
        let rva = text_rva.checked_add(off as u32)?;
        if !rva_in_any(rva, exec_ranges) {
            continue;
        }
        if off == 0 || is_func_boundary_byte(text_bytes[off - 1]) {
            // Prefer sub rsp prologue at start
            if looks_like_x64_prologue(&text_bytes[off..text_bytes.len().min(off + 8)]) {
                return Some(rva);
            }
        }
    }
    // Fallback: nearest boundary with any code
    for delta in 0..=back {
        let off = imm_off - delta;
        let rva = text_rva.checked_add(off as u32)?;
        if !rva_in_any(rva, exec_ranges) {
            continue;
        }
        if off == 0 || is_func_boundary_byte(text_bytes[off - 1]) {
            return Some(rva);
        }
    }
    None
}

fn is_func_boundary_byte(b: u8) -> bool {
    matches!(b, 0xCC | 0x90 | 0x00 | 0xC3 | 0xC2)
}

fn looks_like_x64_prologue(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    // sub rsp, imm8: 48 83 EC xx
    if bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC {
        return true;
    }
    // sub rsp, imm32: 48 81 EC
    if bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC {
        return true;
    }
    // mov [rsp+…], … common
    if bytes[0] == 0x48 && bytes[1] == 0x89 {
        return true;
    }
    false
}

/// Detect cookie/complement writebacks with strict complement = NOT(same reg) store.
///
/// Real MSVC x64 order (B6): store cookie, `not reg`, store complement to non-adjacent site.
fn function_writes_cookie_and_complement(
    window: &[u8],
    func_rva: u32,
    cookie_rva: u32,
    complement_rva: u32,
) -> bool {
    match cookie_complement_from_security_init_xrefs(window, func_rva) {
        Ok(site) => site.cookie_rva == cookie_rva && site.complement_rva == complement_rva,
        Err(_) => false,
    }
}

/// Parse RIP-relative stores from a `__security_init_cookie` body.
///
/// Fail-closed rules:
/// - cookie store: `mov [rip+disp], r64` targeting the cookie site
/// - complement store: same register must have been `not`-ed, then stored
/// - cookie and complement RVAs must differ
pub fn cookie_complement_from_security_init_xrefs(
    window: &[u8],
    func_rva: u32,
) -> Result<CookieComplementSite, MsvcCrtResolveError> {
    if !window_contains_security_cookie_sentinel(window) {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "security_init_missing_sentinel",
        });
    }

    let mut notted_regs: u8 = 0;
    let mut cookie_rva: Option<u32> = None;
    let mut complement_rva: Option<u32> = None;

    let mut i = 0usize;
    while i + 3 < window.len() {
        // REX.W not r64: 48 F7 D0..D7
        if window[i] == 0x48 && window[i + 1] == 0xF7 && (window[i + 2] & 0xF8) == 0xD0 {
            let reg = window[i + 2] & 0x07;
            notted_regs |= 1u8 << reg;
            i += 3;
            continue;
        }

        // mov [rip+disp32], r64 — ModRM: mod=00 rm=101, reg field = source
        if i + 7 <= window.len()
            && window[i] == 0x48
            && window[i + 1] == 0x89
            && (window[i + 2] & 0xC7) == 0x05
        {
            let src_reg = (window[i + 2] >> 3) & 0x07;
            let disp = i32::from_le_bytes(window[i + 3..i + 7].try_into().unwrap());
            let next_ip = i64::from(func_rva) + i as i64 + 7;
            let target = next_ip.wrapping_add(i64::from(disp));
            if target >= 0 && target <= i64::from(u32::MAX) {
                let t = target as u32;
                if (notted_regs & (1u8 << src_reg)) != 0 {
                    // Store after NOT → complement writeback (same register).
                    if complement_rva.is_none() {
                        complement_rva = Some(t);
                    }
                } else if cookie_rva.is_none() {
                    // Store before NOT → cookie writeback.
                    cookie_rva = Some(t);
                }
            }
            i += 7;
            continue;
        }

        i += 1;
    }

    let cookie_rva = cookie_rva.ok_or(MsvcCrtResolveError::InvalidCookieSite)?;
    let complement_rva = complement_rva.ok_or(MsvcCrtResolveError::SemanticReject {
        reason: "complement_store_without_not",
    })?;
    if cookie_rva == complement_rva {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "cookie_and_complement_identical",
        });
    }
    Ok(CookieComplementSite {
        cookie_rva,
        complement_rva,
    })
}

/// Shared pure classifier: true if `bytes` look like `__scrt_common_main_seh`.
///
/// Accepts:
/// - B6/MSVC14 form: `mov [rsp+8], rbx; push rdi; sub rsp, imm; mov ecx, 1; call`
/// - Legacy SEH form: `sub rsp, imm` + `mov qword ptr [rsp+20h], 0FFFFFFFE`
///
/// Always rejects TLS / dynamic-initializer helpers first.
#[must_use]
pub fn is_scrt_common_main_seh_bytes(bytes: &[u8]) -> bool {
    if is_tls_or_dynamic_init_helper_bytes(bytes) {
        return false;
    }
    looks_like_scrt_common_main_seh(bytes)
}

/// Shared pure classifier: TLS callback / dynamic-initializer helper.
///
/// Accepts B6 real shape (`cmp edx, 2` / early `gs:[58h]` TEB TLS pointer) and
/// classic `sub rsp,28; mov ecx, imm32` dynamic-init stubs.
#[must_use]
pub fn is_tls_or_dynamic_init_helper_bytes(bytes: &[u8]) -> bool {
    looks_like_tls_or_dynamic_init_helper(bytes)
}

/// Shared: DEFAULT SecurityCookie sentinel present in window.
#[must_use]
pub fn window_contains_security_cookie_sentinel(bytes: &[u8]) -> bool {
    let sent = DEFAULT_SECURITY_COOKIE.to_le_bytes();
    bytes.windows(8).any(|w| w == sent)
}

// ---------------------------------------------------------------------------
// __scrt_common_main_seh semantic validation
// ---------------------------------------------------------------------------

/// Validate that `rva` is a plausible `__scrt_common_main_seh` body.
pub fn validate_scrt_common_main_seh(
    text_bytes: &[u8],
    text_rva: u32,
    rva: u32,
    exec_ranges: &[ExecRange],
) -> Result<(), MsvcCrtResolveError> {
    if !rva_in_any(rva, exec_ranges) {
        return Err(MsvcCrtResolveError::TargetNotExecutable {
            rva,
            role: "scrt_common_main_seh",
        });
    }
    if rva < text_rva {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "common_main_rva_before_text",
        });
    }
    let off = (rva - text_rva) as usize;
    if off >= text_bytes.len() {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "common_main_rva_out_of_bounds",
        });
    }
    let window = &text_bytes[off..text_bytes.len().min(off + 0x40)];
    if is_tls_or_dynamic_init_helper_bytes(window) {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "tls_or_dynamic_initializer_helper",
        });
    }
    if !is_scrt_common_main_seh_bytes(window) {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "not_scrt_common_main_seh_prologue",
        });
    }
    Ok(())
}

fn looks_like_scrt_common_main_seh(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }

    // B6 / MSVC14 CRT: mov [rsp+8], rbx; push rdi; sub rsp, imm8; mov ecx, 1; call
    // 48 89 5C 24 08  57  48 83 EC xx  B9 01 00 00 00  E8
    if bytes[0] == 0x48
        && bytes[1] == 0x89
        && bytes[2] == 0x5C
        && bytes[3] == 0x24
        && bytes[4] == 0x08
        && bytes[5] == 0x57
        && bytes[6] == 0x48
        && bytes[7] == 0x83
        && bytes[8] == 0xEC
        && bytes.len() >= 16
        && bytes[10] == 0xB9
        && bytes[11] == 0x01
        && bytes[12] == 0x00
        && bytes[13] == 0x00
        && bytes[14] == 0x00
        && bytes[15] == 0xE8
    {
        return true;
    }

    // Legacy SEH CRT main: sub rsp, imm + mov qword ptr [rsp+20h], 0FFFFFFFE
    let has_sub = bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC;
    let has_sub32 = bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC;
    if has_sub || has_sub32 {
        let needle: &[u8] = &[0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE, 0xFF, 0xFF, 0xFF];
        if bytes.windows(needle.len()).any(|w| w == needle) {
            return true;
        }
    }
    false
}

fn looks_like_tls_or_dynamic_init_helper(bytes: &[u8]) -> bool {
    if bytes.len() < 10 {
        return false;
    }
    // B6 real TLS/dyn-init helper at 0x165290: cmp edx, 2; jne …
    if bytes[0] == 0x83 && bytes[1] == 0xFA && bytes[2] == 0x02 {
        return true;
    }
    // Early TEB ThreadLocalStoragePointer: mov rax, gs:[58h]
    // 65 48 8B 04 25 58 00 00 00
    let teb_tls: &[u8] = &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00];
    if bytes.windows(teb_tls.len()).any(|w| w == teb_tls) {
        return true;
    }
    // Classic dynamic initializer: sub rsp,28; mov ecx, imm32
    if bytes[0] == 0x48
        && bytes[1] == 0x83
        && bytes[2] == 0xEC
        && bytes[3] == 0x28
        && bytes[4] == 0xB9
    {
        return true;
    }
    false
}

/// Reject using a TLS/dynamic-initializer helper as common-main.
pub fn reject_if_tls_helper_as_common_main(
    text_bytes: &[u8],
    text_rva: u32,
    rva: u32,
) -> Result<(), MsvcCrtResolveError> {
    if rva < text_rva {
        return Ok(());
    }
    let off = (rva - text_rva) as usize;
    if off >= text_bytes.len() {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "target_out_of_bounds",
        });
    }
    let window = &text_bytes[off..text_bytes.len().min(off + 0x40)];
    if is_tls_or_dynamic_init_helper_bytes(window) {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "tls_helper_rejected_as_common_main",
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Wrapper encoding + validation
// ---------------------------------------------------------------------------

/// Encode the 18-byte MSVC PE-entry wrapper. Fail-closed on rel32 overflow.
pub fn encode_msvc_oep_wrapper(
    oep_rva: u32,
    security_init_cookie_rva: u32,
    scrt_common_main_seh_rva: u32,
) -> Result<[u8; MSVC_OEP_WRAPPER_LEN], MsvcCrtResolveError> {
    // Win64 stack alignment contract: sub/add rsp, 28h only (no ±8 workaround).
    let mut stub = [
        0x48, 0x83, 0xEC, 0x28, // sub rsp, 28h
        0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32
        0x48, 0x83, 0xC4, 0x28, // add rsp, 28h
        0xE9, 0x00, 0x00, 0x00, 0x00, // jmp rel32
    ];

    let call_disp = checked_rel32(oep_rva.wrapping_add(9), security_init_cookie_rva)
        .ok_or(MsvcCrtResolveError::Rel32Overflow { role: "call" })?;
    stub[5..9].copy_from_slice(&call_disp.to_le_bytes());

    let jmp_disp = checked_rel32(oep_rva.wrapping_add(18), scrt_common_main_seh_rva)
        .ok_or(MsvcCrtResolveError::Rel32Overflow { role: "jmp" })?;
    stub[14..18].copy_from_slice(&jmp_disp.to_le_bytes());

    Ok(stub)
}

fn checked_rel32(next_ip: u32, target: u32) -> Option<i32> {
    let disp = i64::from(target).checked_sub(i64::from(next_ip))?;
    if disp < i64::from(i32::MIN) || disp > i64::from(i32::MAX) {
        return None;
    }
    Some(disp as i32)
}

/// Decode call/jmp targets from an 18-byte wrapper at `oep_rva`.
pub fn decode_msvc_oep_wrapper(stub: &[u8], oep_rva: u32) -> Option<(u32, u32)> {
    if stub.len() < MSVC_OEP_WRAPPER_LEN {
        return None;
    }
    if !(stub[0] == 0x48
        && stub[1] == 0x83
        && stub[2] == 0xEC
        && stub[3] == 0x28
        && stub[4] == 0xE8
        && stub[9] == 0x48
        && stub[10] == 0x83
        && stub[11] == 0xC4
        && stub[12] == 0x28
        && stub[13] == 0xE9)
    {
        return None;
    }
    // Enforce stack contract: imm must be 0x28 on both sub and add (no ±8).
    if stub[3] != 0x28 || stub[12] != 0x28 {
        return None;
    }
    let call_rel = i32::from_le_bytes(stub[5..9].try_into().ok()?);
    let jmp_rel = i32::from_le_bytes(stub[14..18].try_into().ok()?);
    let call_tgt = checked_rel32_target(oep_rva.wrapping_add(9), call_rel)?;
    let jmp_tgt = checked_rel32_target(oep_rva.wrapping_add(18), jmp_rel)?;
    Some((call_tgt, jmp_tgt))
}

fn checked_rel32_target(next_ip: u32, rel: i32) -> Option<u32> {
    let t = i64::from(next_ip).checked_add(i64::from(rel))?;
    if t < 0 || t > i64::from(u32::MAX) {
        return None;
    }
    Some(t as u32)
}

/// Semantic validation of a strong wrapper's call/jmp targets.
///
/// Rejects the known-wrong S3.10 pair (call common_main / jmp TLS helper) and
/// requires call → cookie-init, jmp → common_main.
pub fn validate_wrapper_targets(
    text_bytes: &[u8],
    text_rva: u32,
    oep_rva: u32,
    call_tgt: u32,
    jmp_tgt: u32,
    site: Option<CookieComplementSite>,
    exec_ranges: &[ExecRange],
) -> Result<(), MsvcCrtResolveError> {
    if !rva_in_any(call_tgt, exec_ranges) {
        return Err(MsvcCrtResolveError::TargetNotExecutable {
            rva: call_tgt,
            role: "security_init_cookie",
        });
    }
    if !rva_in_any(jmp_tgt, exec_ranges) {
        return Err(MsvcCrtResolveError::TargetNotExecutable {
            rva: jmp_tgt,
            role: "scrt_common_main_seh",
        });
    }

    // Call must not land on common_main SEH body; jmp must not be TLS helper.
    reject_if_tls_helper_as_common_main(text_bytes, text_rva, jmp_tgt)?;
    validate_scrt_common_main_seh(text_bytes, text_rva, jmp_tgt, exec_ranges)?;

    // Call target must be __security_init_cookie when site is known.
    if let Some(site) = site {
        let resolved = resolve_security_init_cookie(text_bytes, text_rva, site, exec_ranges)?;
        if call_tgt != resolved {
            return Err(MsvcCrtResolveError::SemanticReject {
                reason: "call_target_is_not_security_init_cookie",
            });
        }
    } else {
        // Without cookie site, still reject if call looks like common_main or TLS helper.
        if validate_scrt_common_main_seh(text_bytes, text_rva, call_tgt, exec_ranges).is_ok() {
            return Err(MsvcCrtResolveError::SemanticReject {
                reason: "call_target_looks_like_common_main",
            });
        }
        reject_if_tls_helper_as_common_main(text_bytes, text_rva, call_tgt).map_err(|_| {
            MsvcCrtResolveError::SemanticReject {
                reason: "call_target_looks_like_tls_helper",
            }
        })?;
        // Require sentinel at call target window.
        if !function_contains_sentinel(text_bytes, text_rva, call_tgt) {
            return Err(MsvcCrtResolveError::SemanticReject {
                reason: "call_target_missing_security_cookie_sentinel",
            });
        }
    }

    let _ = oep_rva;
    Ok(())
}

fn function_contains_sentinel(text_bytes: &[u8], text_rva: u32, func_rva: u32) -> bool {
    if func_rva < text_rva {
        return false;
    }
    let off = (func_rva - text_rva) as usize;
    let window = match text_bytes.get(off..text_bytes.len().min(off + 0x200)) {
        Some(w) => w,
        None => return false,
    };
    let sent = DEFAULT_SECURITY_COOKIE.to_le_bytes();
    window.windows(8).any(|w| w == sent)
}

/// Full offline resolution of both CRT targets (unique / fail-closed).
///
/// Order (B7.2):
/// 1. Full `.text` → `__security_init_cookie` xrefs → cookie_fn + cookie/complement RVAs
/// 2. Optional data slice cross-check (exact site match preferred; fail on live mismatch)
/// 3. Common-main resolve
///
/// `cookie_site` on the returned targets is authoritative and must not be discarded.
pub fn resolve_msvc_crt_targets(
    text_bytes: &[u8],
    text_rva: u32,
    data_bytes: &[u8],
    data_rva: u32,
    exec_ranges: &[ExecRange],
    common_main_hint: Option<u32>,
) -> Result<MsvcCrtTargets, MsvcCrtResolveError> {
    let (cookie_fn, site) =
        resolve_cookie_site_via_security_init_xrefs(text_bytes, text_rva, exec_ranges)?;

    // Optional data cross-check when a data slice is available. Any supplied
    // slice must structurally contain both xref-derived slots.
    if !data_bytes.is_empty() {
        if data_bytes.len() < 16 {
            return Err(MsvcCrtResolveError::SemanticReject {
                reason: "cookie_data_slice_too_short",
            });
        }
        cross_check_cookie_site_with_data(data_bytes, data_rva, site)?;
    }

    let common_main = if let Some(hint) = common_main_hint {
        validate_scrt_common_main_seh(text_bytes, text_rva, hint, exec_ranges)?;
        hint
    } else {
        let mut found: Vec<u32> = Vec::new();
        let end = text_bytes.len().saturating_sub(16);
        for off in 0..end {
            let rva = text_rva.saturating_add(off as u32);
            if !rva_in_any(rva, exec_ranges) {
                continue;
            }
            if off > 0 && !is_func_boundary_byte(text_bytes[off - 1]) {
                continue;
            }
            let window = &text_bytes[off..text_bytes.len().min(off + 0x40)];
            if is_scrt_common_main_seh_bytes(window) {
                found.push(rva);
            }
        }
        match found.len() {
            0 => return Err(MsvcCrtResolveError::MissingCommonMain),
            1 => found[0],
            n => return Err(MsvcCrtResolveError::AmbiguousCommonMain(n)),
        }
    };

    if cookie_fn == common_main {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "cookie_and_common_main_identical",
        });
    }

    // Ensure site still validates against resolved cookie_fn.
    let _ = resolve_security_init_cookie(text_bytes, text_rva, site, exec_ranges)?;

    Ok(MsvcCrtTargets {
        security_init_cookie_rva: cookie_fn,
        scrt_common_main_seh_rva: common_main,
        cookie_site: site,
    })
}

/// Offline resolve with structural section selection (name-independent).
///
/// 1. Xref cookie site from full `.text`
/// 2. Select R+W non-X section containing both RVAs
/// 3. Optional exact-length data cross-check on that section
/// 4. Common-main resolve (hint or unique scan)
pub fn resolve_msvc_crt_targets_with_sections(
    text_bytes: &[u8],
    text_rva: u32,
    sections: &[PeSectionView],
    data_bytes: Option<&[u8]>,
    exec_ranges: &[ExecRange],
    common_main_hint: Option<u32>,
) -> Result<MsvcCrtTargets, MsvcCrtResolveError> {
    let (cookie_fn, site) =
        resolve_cookie_site_via_security_init_xrefs(text_bytes, text_rva, exec_ranges)?;

    let storage = select_cookie_storage_section(sections, site)?;

    if let Some(data) = data_bytes {
        // Exact-length contract: caller must pass full section virtual_size bytes.
        if data.len() != storage.virtual_size as usize {
            return Err(MsvcCrtResolveError::SemanticReject {
                reason: "cookie_section_read_length_mismatch",
            });
        }
        cross_check_cookie_site_with_data(data, storage.virtual_address, site)?;
    }

    let common_main = if let Some(hint) = common_main_hint {
        validate_scrt_common_main_seh(text_bytes, text_rva, hint, exec_ranges)?;
        hint
    } else {
        let mut found: Vec<u32> = Vec::new();
        let end = text_bytes.len().saturating_sub(16);
        for off in 0..end {
            let rva = text_rva.saturating_add(off as u32);
            if !rva_in_any(rva, exec_ranges) {
                continue;
            }
            if off > 0 && !is_func_boundary_byte(text_bytes[off - 1]) {
                continue;
            }
            let window = &text_bytes[off..text_bytes.len().min(off + 0x40)];
            if is_scrt_common_main_seh_bytes(window) {
                found.push(rva);
            }
        }
        match found.len() {
            0 => return Err(MsvcCrtResolveError::MissingCommonMain),
            1 => found[0],
            n => return Err(MsvcCrtResolveError::AmbiguousCommonMain(n)),
        }
    };

    if cookie_fn == common_main {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "cookie_and_common_main_identical",
        });
    }

    let _ = resolve_security_init_cookie(text_bytes, text_rva, site, exec_ranges)?;

    Ok(MsvcCrtTargets {
        security_init_cookie_rva: cookie_fn,
        scrt_common_main_seh_rva: common_main,
        cookie_site: site,
    })
}

/// Verify the **authoritative** xref-derived cookie/complement slots in `data`.
///
/// B7.2.1 fail-closed:
/// - both 8-byte slots must lie in the slice;
/// - cookie slot must be a legal non-zero plausible cookie;
/// - complement slot must equal `!cookie` exactly;
/// - no 0/default exception that masks a mismatch;
/// - an unrelated pair elsewhere in the section does **not** validate a bad site.
fn cross_check_cookie_site_with_data(
    data_bytes: &[u8],
    data_rva: u32,
    site: CookieComplementSite,
) -> Result<(), MsvcCrtResolveError> {
    if data_bytes.len() < 16 {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "cookie_data_slice_too_short",
        });
    }
    // Bounds: both slots must lie inside the provided slice when claimed as storage.
    let cookie_off = match site.cookie_rva.checked_sub(data_rva) {
        Some(d) => d as usize,
        None => {
            return Err(MsvcCrtResolveError::SemanticReject {
                reason: "cookie_site_out_of_data_slice",
            })
        }
    };
    let comp_off = match site.complement_rva.checked_sub(data_rva) {
        Some(d) => d as usize,
        None => {
            return Err(MsvcCrtResolveError::SemanticReject {
                reason: "cookie_site_out_of_data_slice",
            })
        }
    };
    let cookie_end = cookie_off
        .checked_add(8)
        .ok_or(MsvcCrtResolveError::SemanticReject {
            reason: "cookie_site_out_of_data_slice",
        })?;
    let comp_end = comp_off
        .checked_add(8)
        .ok_or(MsvcCrtResolveError::SemanticReject {
            reason: "cookie_site_out_of_data_slice",
        })?;
    if cookie_end > data_bytes.len() || comp_end > data_bytes.len() {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "cookie_site_out_of_data_slice",
        });
    }

    let cookie = u64::from_le_bytes(data_bytes[cookie_off..cookie_end].try_into().unwrap());
    let complement = u64::from_le_bytes(data_bytes[comp_off..comp_end].try_into().unwrap());

    // Authoritative cookie slot itself must be a legal non-zero cookie.
    // Zero/default exceptions that previously masked mismatch are removed.
    if !is_plausible_cookie(cookie) {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: if cookie == 0 {
                "zero_cookie_xref_site"
            } else {
                "cookie_slot_not_plausible"
            },
        });
    }
    // Complement must exactly equal !cookie at the authoritative complement RVA.
    if complement != !cookie {
        return Err(MsvcCrtResolveError::SemanticReject {
            reason: "cookie_complement_mismatch",
        });
    }
    Ok(())
}

fn rva_in_any(rva: u32, ranges: &[ExecRange]) -> bool {
    ranges.iter().any(|r| r.contains(rva))
}

// ---------------------------------------------------------------------------
// Live write path (fail-closed)
// ---------------------------------------------------------------------------

/// Write synthetic MSVC OEP with fail-closed validation.
///
/// Partial write, rel32 overflow, or non-executable targets → error (no silent OK).
pub fn write_msvc_oep_x64_validated(
    debugger: &mut dyn DebuggerCore,
    h_process: windows::Win32::Foundation::HANDLE,
    oep: usize,
    security_init_cookie_addr: usize,
    scrt_common_main_seh_addr: usize,
    image_base: usize,
    exec_ranges: &[ExecRange],
) -> Result<(), ThemidaError> {
    let oep_rva = va_to_rva(oep, image_base)?;
    let cookie_rva = va_to_rva(security_init_cookie_addr, image_base)?;
    let main_rva = va_to_rva(scrt_common_main_seh_addr, image_base)?;

    if !rva_in_any(cookie_rva, exec_ranges) {
        return Err(ThemidaError::OepDetectionFailed(format!(
            "security_init_cookie {cookie_rva:#x} not executable"
        )));
    }
    if !rva_in_any(main_rva, exec_ranges) {
        return Err(ThemidaError::OepDetectionFailed(format!(
            "scrt_common_main_seh {main_rva:#x} not executable"
        )));
    }

    let stub = encode_msvc_oep_wrapper(oep_rva, cookie_rva, main_rva).map_err(|e| {
        ThemidaError::OepDetectionFailed(format!("MSVC OEP encode fail-closed: {e}"))
    })?;

    use windows::Win32::System::Memory::{
        VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };

    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    unsafe {
        VirtualProtectEx(
            h_process,
            oep as *const std::ffi::c_void,
            stub.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|e| {
        ThemidaError::Debugger(format!(
            "VirtualProtectEx at OEP {oep:#x} for MSVC stub: {e}"
        ))
    })?;

    let written = debugger
        .write_memory(oep, &stub)
        .map_err(|e| ThemidaError::Debugger(format!("write MSVC x64 OEP stub: {e}")))?;

    if written < stub.len() {
        warn!(
            expected = stub.len(),
            actual = written,
            "Partial write of MSVC x64 OEP stub — fail-closed"
        );
        return Err(ThemidaError::OepDetectionFailed(format!(
            "partial write of MSVC x64 OEP stub ({written}/{})",
            stub.len()
        )));
    }

    info!(
        "MSVC x64 OEP written at {oep:#x}: call → {security_init_cookie_addr:#x}, jmp → {scrt_common_main_seh_addr:#x}"
    );
    Ok(())
}

fn va_to_rva(va: usize, image_base: usize) -> Result<u32, ThemidaError> {
    if va < image_base {
        return Err(ThemidaError::OepDetectionFailed(format!(
            "VA {va:#x} below image base {image_base:#x}"
        )));
    }
    let rva = va - image_base;
    if rva > u32::MAX as usize {
        return Err(ThemidaError::OepDetectionFailed(format!(
            "RVA overflow for VA {va:#x}"
        )));
    }
    Ok(rva as u32)
}

/// Fail-closed full-section read contract (pure).
///
/// Process `.text` / `.data` reads must return exactly `requested` bytes.
pub fn require_full_section_read(
    actual: usize,
    requested: usize,
    section: &'static str,
) -> Result<(), String> {
    if actual != requested {
        return Err(format!(
            "short {section} read for CRT resolve (got {actual}, requested {requested})"
        ));
    }
    Ok(())
}

/// Read full `.text`, resolve cookie site via xrefs, structurally select R+W
/// storage section (name-independent), exact-length-read that section, resolve.
///
/// Fail-closed: section reads must return exactly `requested` bytes.
/// Does **not** require a section named `.data`.
pub fn resolve_msvc_crt_targets_from_process(
    debugger: &dyn DebuggerCore,
    image_base: usize,
    text_rva: u32,
    text_size: u32,
    sections: &[PeSectionView],
    exec_ranges: &[ExecRange],
    common_main_hint_va: Option<usize>,
) -> Result<MsvcCrtTargets, ThemidaError> {
    let text_req = text_size as usize;
    let mut text = vec![0u8; text_req];
    let n = debugger
        .read_memory(image_base + text_rva as usize, &mut text)
        .map_err(|e| ThemidaError::Debugger(format!("read .text for CRT resolve: {e}")))?;
    require_full_section_read(n, text_req, ".text").map_err(ThemidaError::OepDetectionFailed)?;

    let (cookie_fn, site) =
        resolve_cookie_site_via_security_init_xrefs(&text, text_rva, exec_ranges).map_err(|e| {
            ThemidaError::OepDetectionFailed(format!(
                "MSVC CRT cookie xref resolve fail-closed: {e}"
            ))
        })?;
    let _ = cookie_fn;

    let storage = select_cookie_storage_section(sections, site).map_err(|e| {
        ThemidaError::OepDetectionFailed(format!(
            "MSVC CRT cookie storage section fail-closed: {e}"
        ))
    })?;

    let data_req = storage.virtual_size as usize;
    let mut data = vec![0u8; data_req];
    let n = debugger
        .read_memory(image_base + storage.virtual_address as usize, &mut data)
        .map_err(|e| {
            ThemidaError::Debugger(format!(
                "read cookie storage section {:#x} for CRT resolve: {e}",
                storage.virtual_address
            ))
        })?;
    require_full_section_read(n, data_req, "cookie_storage")
        .map_err(ThemidaError::OepDetectionFailed)?;

    let hint = common_main_hint_va
        .map(|va| va_to_rva(va, image_base))
        .transpose()?;

    resolve_msvc_crt_targets_with_sections(
        &text,
        text_rva,
        sections,
        Some(&data),
        exec_ranges,
        hint,
    )
    .map_err(|e| {
        ThemidaError::OepDetectionFailed(format!("MSVC CRT target resolve fail-closed: {e}"))
    })
}

// ---------------------------------------------------------------------------
// FTraceMSVCOEP state helpers (pure; no live process)
// ---------------------------------------------------------------------------

/// Enter FTraceMSVCOEP: preserve current address as common-main candidate.
///
/// Never stores the hit as `msvc_init_cookie`.
pub fn ftrace_enter_preserve_common_main(
    msvc_common_main_seh: &mut usize,
    msvc_init_cookie: &mut usize,
    msvc_oep: &mut usize,
    trace_msvc_oep: &mut bool,
    common_main_candidate: usize,
    oep_stub: usize,
) {
    *msvc_common_main_seh = common_main_candidate;
    *msvc_init_cookie = 0;
    *msvc_oep = oep_stub;
    *trace_msvc_oep = true;
}

/// Common-main hint used at FTrace synthesis time.
///
/// Returns the preserved candidate only — never the next arbitrary `.text` hit.
#[must_use]
pub fn ftrace_common_main_hint(
    preserved_common_main: usize,
    _next_text_hit: usize,
) -> Option<usize> {
    if preserved_common_main != 0 {
        Some(preserved_common_main)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests — real B6 fixture windows (source SHA 2DDDAF17…D2871)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// B6 output PE SHA256 (full).
    const B6_SOURCE_SHA256: &str =
        "2DDDAF17AD25D370DDA9C0FBEB8A17C1E6A491DB1222F279D70F8420AB5D2871";

    const B6_WRAPPER: u32 = 0x165F6C;
    const B6_COOKIE_FN: u32 = 0x1661F0;
    const B6_COMMON_MAIN: u32 = 0x165DF8;
    const B6_TLS_HELPER: u32 = 0x165290;
    const B6_COOKIE_RVA: u32 = 0x1F6F80;
    const B6_COMPLEMENT_RVA: u32 = 0x1F6FC0;

    const TEXT_SLICE_RVA: u32 = 0x165000;
    const DATA_SLICE_RVA: u32 = 0x1F6F00;

    fn fixture_bytes(name: &str) -> &'static [u8] {
        match name {
            "common_main_165df8.bin" => include_bytes!("fixtures/common_main_165df8.bin"),
            "tls_helper_165290.bin" => include_bytes!("fixtures/tls_helper_165290.bin"),
            "cookie_init_1661f0.bin" => include_bytes!("fixtures/cookie_init_1661f0.bin"),
            "wrapper_wrong_165f6c.bin" => include_bytes!("fixtures/wrapper_wrong_165f6c.bin"),
            "cookie_1f6f80.bin" => include_bytes!("fixtures/cookie_1f6f80.bin"),
            "complement_1f6fc0.bin" => include_bytes!("fixtures/complement_1f6fc0.bin"),
            "text_crt_165000_166300.bin" => include_bytes!("fixtures/text_crt_165000_166300.bin"),
            "data_1f6f00_1f7000.bin" => include_bytes!("fixtures/data_1f6f00_1f7000.bin"),
            _ => panic!("unknown fixture {name}"),
        }
    }

    fn exec_text() -> Vec<ExecRange> {
        vec![ExecRange {
            rva_start: 0x1000,
            rva_end: 0x1B0000,
        }]
    }

    fn real_text_data() -> (Vec<u8>, u32, Vec<u8>, u32) {
        (
            fixture_bytes("text_crt_165000_166300.bin").to_vec(),
            TEXT_SLICE_RVA,
            fixture_bytes("data_1f6f00_1f7000.bin").to_vec(),
            DATA_SLICE_RVA,
        )
    }

    #[test]
    fn real_b6_fixture_source_tag() {
        let src = include_str!("fixtures/SOURCE.txt");
        assert!(src.contains(B6_SOURCE_SHA256));
        // Stable UTF-8/JSON provenance (B7.2) — no mojibake path required.
        assert!(src.trim_start().starts_with('{'));
        assert!(src.contains("\"source_sha256\""));
        assert!(
            src.contains(format!("\"{B6_SOURCE_SHA256}\"").as_str())
                || src.contains(B6_SOURCE_SHA256)
        );
        assert!(src.contains("\"extracted\""));
        assert!(src.contains("0x1F3000") || src.contains("0x1f3000"));
        // UTF-8: no replacement chars from mojibake source path.
        assert!(!src.contains('\u{FFFD}'));
        assert!(src.is_char_boundary(src.len()));
    }

    #[test]
    fn real_b6_common_main_165df8_accepted() {
        let bytes = fixture_bytes("common_main_165df8.bin");
        assert!(
            is_scrt_common_main_seh_bytes(bytes),
            "real B6 0x165DF8 must be accepted as common-main"
        );
        assert!(!is_tls_or_dynamic_init_helper_bytes(bytes));
        let (text, text_rva, _, _) = real_text_data();
        validate_scrt_common_main_seh(&text, text_rva, B6_COMMON_MAIN, &exec_text())
            .expect("validate real common_main");
    }

    #[test]
    fn real_b6_tls_helper_165290_rejected() {
        let bytes = fixture_bytes("tls_helper_165290.bin");
        assert!(
            is_tls_or_dynamic_init_helper_bytes(bytes),
            "real B6 0x165290 must classify as TLS/dyn-init helper"
        );
        assert!(!is_scrt_common_main_seh_bytes(bytes));
        let (text, text_rva, _, _) = real_text_data();
        let err = validate_scrt_common_main_seh(&text, text_rva, B6_TLS_HELPER, &exec_text());
        assert!(err.is_err(), "TLS helper must not validate as common-main");
        let err2 = reject_if_tls_helper_as_common_main(&text, text_rva, B6_TLS_HELPER);
        assert!(err2.is_err());
    }

    #[test]
    fn real_b6_cookie_init_1661f0_resolved() {
        let (text, text_rva, data, data_rva) = real_text_data();
        let ranges = exec_text();
        let (fn_rva, site) =
            resolve_cookie_site_via_security_init_xrefs(&text, text_rva, &ranges).expect("xref");
        assert_eq!(fn_rva, B6_COOKIE_FN);
        assert_eq!(site.cookie_rva, B6_COOKIE_RVA);
        assert_eq!(site.complement_rva, B6_COMPLEMENT_RVA);
        assert_ne!(site.complement_rva, site.cookie_rva.wrapping_add(8));

        let resolved =
            resolve_security_init_cookie(&text, text_rva, site, &ranges).expect("resolve");
        assert_eq!(resolved, B6_COOKIE_FN);

        // Data pair locator also finds non-adjacent pair.
        let data_site = find_cookie_complement_site(&data, data_rva).expect("data site");
        assert_eq!(data_site.cookie_rva, B6_COOKIE_RVA);
        assert_eq!(data_site.complement_rva, B6_COMPLEMENT_RVA);
    }

    #[test]
    fn real_b6_old_wrapper_rejected() {
        let (text, text_rva, _, _) = real_text_data();
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        // Historical wrong: call common_main, jmp TLS helper
        let err = validate_wrapper_targets(
            &text,
            text_rva,
            B6_WRAPPER,
            B6_COMMON_MAIN,
            B6_TLS_HELPER,
            Some(site),
            &exec_text(),
        );
        assert!(err.is_err(), "old wrong targets must be rejected: {err:?}");
    }

    #[test]
    fn real_b6_corrected_targets_accepted() {
        let (text, text_rva, _, _) = real_text_data();
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        validate_wrapper_targets(
            &text,
            text_rva,
            B6_WRAPPER,
            B6_COOKIE_FN,
            B6_COMMON_MAIN,
            Some(site),
            &exec_text(),
        )
        .expect("corrected call/jmp must be accepted");
        let stub = encode_msvc_oep_wrapper(B6_WRAPPER, B6_COOKIE_FN, B6_COMMON_MAIN).unwrap();
        let (c, j) = decode_msvc_oep_wrapper(&stub, B6_WRAPPER).unwrap();
        assert_eq!(c, B6_COOKIE_FN);
        assert_eq!(j, B6_COMMON_MAIN);
    }

    #[test]
    fn ftrace_preserves_common_main_hit() {
        let mut common = 0usize;
        let mut cookie = 0usize;
        let mut oep = 0usize;
        let mut trace = false;
        ftrace_enter_preserve_common_main(
            &mut common,
            &mut cookie,
            &mut oep,
            &mut trace,
            0x1401_65DF8,
            0x1401_65F6C,
        );
        assert_eq!(common, 0x1401_65DF8);
        assert_eq!(cookie, 0);
        assert_eq!(oep, 0x1401_65F6C);
        assert!(trace);
    }

    #[test]
    fn next_text_hit_never_replaces_common_main() {
        let preserved = 0x1401_65DF8usize;
        let next_hit = 0x1401_65290usize; // TLS helper
        let hint = ftrace_common_main_hint(preserved, next_hit);
        assert_eq!(hint, Some(preserved));
        assert_ne!(hint, Some(next_hit));
        // Empty preserve → no hint (fail closed to scanner)
        assert_eq!(ftrace_common_main_hint(0, next_hit), None);
    }

    #[test]
    fn complement_store_without_not_rejected() {
        // Synthetic body: sentinel + cookie store + complement store WITHOUT not.
        let func_rva = 0x1000u32;
        let site = CookieComplementSite {
            cookie_rva: 0x2000,
            complement_rva: 0x2040,
        };
        let mut body = Vec::new();
        body.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        body.extend_from_slice(&[0x48, 0xB8]);
        body.extend_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        // store cookie
        let s1 = body.len();
        body.extend_from_slice(&[0x48, 0x89, 0x05, 0, 0, 0, 0]);
        let n1 = func_rva as i64 + s1 as i64 + 7;
        let d1 = (site.cookie_rva as i64 - n1) as i32;
        body[s1 + 3..s1 + 7].copy_from_slice(&d1.to_le_bytes());
        // store complement WITHOUT not
        let s2 = body.len();
        body.extend_from_slice(&[0x48, 0x89, 0x05, 0, 0, 0, 0]);
        let n2 = func_rva as i64 + s2 as i64 + 7;
        let d2 = (site.complement_rva as i64 - n2) as i32;
        body[s2 + 3..s2 + 7].copy_from_slice(&d2.to_le_bytes());
        body.extend_from_slice(&[0xC3]);

        let err = cookie_complement_from_security_init_xrefs(&body, func_rva);
        assert!(
            matches!(
                err,
                Err(MsvcCrtResolveError::SemanticReject {
                    reason: "complement_store_without_not"
                })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn short_text_read_fails_closed() {
        let err = require_full_section_read(0x800, 0x1000, ".text").unwrap_err();
        assert!(err.contains("short .text read"));
        assert!(require_full_section_read(0x1000, 0x1000, ".text").is_ok());
    }

    #[test]
    fn short_data_read_fails_closed() {
        let err = require_full_section_read(0x100, 0x200, ".data").unwrap_err();
        assert!(err.contains("short .data read"));
        assert!(require_full_section_read(0x200, 0x200, ".data").is_ok());
    }

    #[test]
    fn wrapper_win64_stack_alignment_contract() {
        let stub = encode_msvc_oep_wrapper(B6_WRAPPER, B6_COOKIE_FN, B6_COMMON_MAIN).unwrap();
        assert_eq!(&stub[0..4], &[0x48, 0x83, 0xEC, 0x28]);
        assert_eq!(&stub[9..13], &[0x48, 0x83, 0xC4, 0x28]);
        assert_eq!(stub[3], stub[12]);
        assert_eq!(stub[4], 0xE8);
        assert_eq!(stub[13], 0xE9);
    }

    #[test]
    fn rel32_overflow_fails_closed() {
        let err = encode_msvc_oep_wrapper(0x1000, 0xF000_0000, 0x1000);
        assert!(matches!(
            err,
            Err(MsvcCrtResolveError::Rel32Overflow { .. })
        ));
    }

    #[test]
    fn real_b6_resolve_targets_with_preserved_hint() {
        let (text, text_rva, data, data_rva) = real_text_data();
        let t = resolve_msvc_crt_targets(
            &text,
            text_rva,
            &data,
            data_rva,
            &exec_text(),
            Some(B6_COMMON_MAIN),
        )
        .expect("resolve");
        assert_eq!(t.security_init_cookie_rva, B6_COOKIE_FN);
        assert_eq!(t.scrt_common_main_seh_rva, B6_COMMON_MAIN);
        // CookieComplementSite must not be discarded after resolve.
        assert_eq!(t.cookie_site.cookie_rva, B6_COOKIE_RVA);
        assert_eq!(t.cookie_site.complement_rva, B6_COMPLEMENT_RVA);
    }

    // -----------------------------------------------------------------------
    // B7.2 — section-name-independent cookie-site plumbing
    // -----------------------------------------------------------------------

    /// B6 anonymous RW section: RVA 0x1F3000, VSize 0xA5CC, chars R+W non-X.
    const B6_ANON_RW_VA: u32 = 0x1F3000;
    const B6_ANON_RW_VSIZE: u32 = 0xA5CC;
    const B6_ANON_RW_CHARS: u32 = 0xC000_0040; // READ|WRITE|INITIALIZED_DATA

    fn b6_blank_name_sections() -> Vec<PeSectionView> {
        vec![
            PeSectionView {
                virtual_address: 0x1000,
                virtual_size: 0x1A3550,
                characteristics: 0x6000_0020, // R+X
            },
            PeSectionView {
                virtual_address: 0x1A5000,
                virtual_size: 0x4D628,
                characteristics: 0x4000_0040, // R only
            },
            PeSectionView {
                virtual_address: B6_ANON_RW_VA,
                virtual_size: B6_ANON_RW_VSIZE,
                characteristics: B6_ANON_RW_CHARS,
            },
            PeSectionView {
                virtual_address: 0x1FE000,
                virtual_size: 0xC36C,
                characteristics: 0x4000_0040,
            },
        ]
    }

    #[test]
    fn real_b6_anonymous_rw_section_selected() {
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        let sec = select_cookie_storage_section(&b6_blank_name_sections(), site)
            .expect("anonymous RW section must be selected");
        assert_eq!(sec.virtual_address, B6_ANON_RW_VA);
        assert_eq!(sec.virtual_size, B6_ANON_RW_VSIZE);
        assert_eq!(sec.characteristics & SCN_MEM_READ, SCN_MEM_READ);
        assert_eq!(sec.characteristics & SCN_MEM_WRITE, SCN_MEM_WRITE);
        assert_eq!(sec.characteristics & SCN_MEM_EXECUTE, 0);
    }

    #[test]
    fn no_literal_data_section_required() {
        // No section named ".data" — only blank-name sections (as in B6).
        let sections = b6_blank_name_sections();
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        assert!(select_cookie_storage_section(&sections, site).is_ok());
        // Guard path no longer hard-fails on missing .data name.
        let src = include_str!("../guard.rs");
        assert!(
            !src.contains("s.name == \".data\""),
            "guard.rs must not require s.name == \".data\""
        );
    }

    #[test]
    fn cookie_and_complement_must_share_section() {
        let sections = vec![
            PeSectionView {
                virtual_address: 0x1F3000,
                virtual_size: 0x1000,
                characteristics: B6_ANON_RW_CHARS,
            },
            PeSectionView {
                virtual_address: 0x1F4000,
                virtual_size: 0x1000,
                characteristics: B6_ANON_RW_CHARS,
            },
        ];
        let site = CookieComplementSite {
            cookie_rva: 0x1F3080,
            complement_rva: 0x1F40C0, // other section
        };
        let err = select_cookie_storage_section(&sections, site).unwrap_err();
        assert!(
            matches!(
                err,
                MsvcCrtResolveError::SemanticReject {
                    reason: "cookie_and_complement_not_same_section"
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn nonwritable_cookie_section_rejected() {
        let sections = vec![PeSectionView {
            virtual_address: B6_ANON_RW_VA,
            virtual_size: B6_ANON_RW_VSIZE,
            characteristics: 0x4000_0040, // READ only
        }];
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        let err = select_cookie_storage_section(&sections, site).unwrap_err();
        assert!(
            matches!(
                err,
                MsvcCrtResolveError::SemanticReject {
                    reason: "cookie_section_not_writable"
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn executable_cookie_section_rejected() {
        let sections = vec![PeSectionView {
            virtual_address: B6_ANON_RW_VA,
            virtual_size: B6_ANON_RW_VSIZE,
            characteristics: 0xE000_0040, // R+W+X
        }];
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        let err = select_cookie_storage_section(&sections, site).unwrap_err();
        assert!(
            matches!(
                err,
                MsvcCrtResolveError::SemanticReject {
                    reason: "cookie_section_executable"
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn real_b6_full_resolver_with_blank_section_names() {
        let (text, text_rva, data, data_rva) = real_text_data();
        let sections = b6_blank_name_sections();
        // Data window is a slice of the anonymous RW section, not full vsize —
        // use empty optional data + structural section select only, or pad.
        let mut full = vec![0u8; B6_ANON_RW_VSIZE as usize];
        let win_off = (data_rva - B6_ANON_RW_VA) as usize;
        full[win_off..win_off + data.len()].copy_from_slice(&data);

        let t = resolve_msvc_crt_targets_with_sections(
            &text,
            text_rva,
            &sections,
            Some(&full),
            &exec_text(),
            Some(B6_COMMON_MAIN),
        )
        .expect("full resolve with blank section names");
        assert_eq!(t.security_init_cookie_rva, B6_COOKIE_FN);
        assert_eq!(t.scrt_common_main_seh_rva, B6_COMMON_MAIN);
        assert_eq!(t.cookie_site.cookie_rva, B6_COOKIE_RVA);
        assert_eq!(t.cookie_site.complement_rva, B6_COMPLEMENT_RVA);
        // Structural select matches anonymous section.
        let sec = select_cookie_storage_section(&sections, t.cookie_site).unwrap();
        assert_eq!(sec.virtual_address, B6_ANON_RW_VA);
    }

    #[test]
    fn xref_cookie_site_propagates_to_targets() {
        let (text, text_rva, data, data_rva) = real_text_data();
        let t = resolve_msvc_crt_targets(
            &text,
            text_rva,
            &data,
            data_rva,
            &exec_text(),
            Some(B6_COMMON_MAIN),
        )
        .unwrap();
        // MsvcCrtTargets.cookie_site is the dump-process authority surface.
        assert_ne!(t.cookie_site.cookie_rva, 0);
        assert_ne!(t.cookie_site.complement_rva, 0);
        assert_eq!(
            t.cookie_site,
            CookieComplementSite {
                cookie_rva: B6_COOKIE_RVA,
                complement_rva: B6_COMPLEMENT_RVA,
            }
        );
    }

    // -----------------------------------------------------------------------
    // B7.2.1 — data cross-check fail-closed on authoritative site
    // -----------------------------------------------------------------------

    #[test]
    fn missing_xref_pair_bytes_fail_closed() {
        // Authoritative RVAs inside slice, but slots are zeros / no pair bytes.
        let data_rva = 0x1F6F00u32;
        let data = vec![0u8; 0x100];
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        let err = cross_check_cookie_site_with_data(&data, data_rva, site).unwrap_err();
        assert!(
            matches!(
                err,
                MsvcCrtResolveError::SemanticReject {
                    reason: "zero_cookie_xref_site"
                }
            ),
            "missing pair bytes must hard-fail: {err:?}"
        );
    }

    #[test]
    fn unrelated_pair_does_not_validate_authoritative_site() {
        // Unrelated valid pair at other offsets must not pass a damaged authoritative site.
        let data_rva = 0x1F6F00u32;
        let mut data = vec![0u8; 0x100];
        // Unrelated DEFAULT pair at +0x00 / +0x10
        data[0..8].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        data[0x10..0x18].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());
        // Authoritative B6 slots zeroed / wrong
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        let err = cross_check_cookie_site_with_data(&data, data_rva, site).unwrap_err();
        assert!(
            matches!(
                err,
                MsvcCrtResolveError::SemanticReject {
                    reason: "zero_cookie_xref_site"
                } | MsvcCrtResolveError::SemanticReject {
                    reason: "cookie_complement_mismatch"
                }
            ),
            "unrelated pair must not validate bad authoritative site: {err:?}"
        );
    }

    #[test]
    fn zero_cookie_xref_site_rejected() {
        let data_rva = 0x1F6F00u32;
        let mut data = vec![0u8; 0x100];
        let cookie_off = (B6_COOKIE_RVA - data_rva) as usize;
        let comp_off = (B6_COMPLEMENT_RVA - data_rva) as usize;
        // cookie = 0, complement = !0 (all ones) — previously could be masked
        data[cookie_off..cookie_off + 8].fill(0);
        data[comp_off..comp_off + 8].copy_from_slice(&(!0u64).to_le_bytes());
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        let err = cross_check_cookie_site_with_data(&data, data_rva, site).unwrap_err();
        assert!(
            matches!(
                err,
                MsvcCrtResolveError::SemanticReject {
                    reason: "zero_cookie_xref_site"
                }
            ),
            "zero cookie slot must hard-fail: {err:?}"
        );
    }

    #[test]
    fn damaged_complement_slot_fail_closed() {
        let data_rva = 0x1F6F00u32;
        let mut data = vec![0u8; 0x100];
        let cookie_off = (B6_COOKIE_RVA - data_rva) as usize;
        let comp_off = (B6_COMPLEMENT_RVA - data_rva) as usize;
        data[cookie_off..cookie_off + 8].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        // Wrong complement (not !cookie)
        data[comp_off..comp_off + 8].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        let site = CookieComplementSite {
            cookie_rva: B6_COOKIE_RVA,
            complement_rva: B6_COMPLEMENT_RVA,
        };
        let err = cross_check_cookie_site_with_data(&data, data_rva, site).unwrap_err();
        assert!(
            matches!(
                err,
                MsvcCrtResolveError::SemanticReject {
                    reason: "cookie_complement_mismatch"
                }
            ),
            "damaged complement must hard-fail: {err:?}"
        );
    }

    #[test]
    fn real_b6_full_resolver_still_passes() {
        let (text, text_rva, data, data_rva) = real_text_data();
        let t = resolve_msvc_crt_targets(
            &text,
            text_rva,
            &data,
            data_rva,
            &exec_text(),
            Some(B6_COMMON_MAIN),
        )
        .expect("real B6 full resolver must still pass");
        assert_eq!(t.security_init_cookie_rva, B6_COOKIE_FN);
        assert_eq!(t.scrt_common_main_seh_rva, B6_COMMON_MAIN);
        assert_eq!(t.cookie_site.cookie_rva, B6_COOKIE_RVA);
        assert_eq!(t.cookie_site.complement_rva, B6_COMPLEMENT_RVA);

        // Direct cross-check on fixture data also passes.
        cross_check_cookie_site_with_data(&data, data_rva, t.cookie_site)
            .expect("authoritative B6 slots must validate");
    }
}
