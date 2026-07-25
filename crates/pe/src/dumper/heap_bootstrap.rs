//! Reinitialize stale CRT heap state before transferring control to the OEP.

use std::collections::{HashMap, HashSet};

use tracing::{info, warn};

use crate::header::PeHeader;
use crate::import_table::ImportTableBuilder;

use super::container_snapshot::ContainerSnapshot;
use super::heap_global_snapshot::HeapGlobalSnapshot;
use super::types::ContainerRestoreMode;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const STUB_SIZE: usize = 26;
const MAX_LOAD_TO_CALL_DISTANCE: usize = 48;

const HEAP_APIS: [&str; 3] = ["HeapAlloc", "HeapReAlloc", "HeapFree"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapBootstrap {
    heap_global_rva: u32,
    get_process_heap_iat_rva: u32,
}

/// Install heap / container bootstrap according to [`ContainerRestoreMode`].
///
/// Returns the **PE entry point** to write (CRT EP unchanged for PostCrt;
/// bootstrap RVA only for PreCrt / simple heap EP stubs).
pub(crate) fn install_heap_bootstrap(
    pe: &mut PeHeader,
    dump_buf: &mut [u8],
    imports: &ImportTableBuilder,
    original_entry_point: u32,
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    restore_mode: ContainerRestoreMode,
    // Cookie storage RVA captured from the late dump (before early overlay).
    cookie_rva: Option<u32>,
    // Optional AHK call-obfuscation cookie mirror (src,dst) image RVAs.
    cookie_mirror: Option<(u32, u32)>,
    _debugger: Option<&mut dyn mida_core::DebuggerCore>,
) -> Option<u32> {
    if !pe.is_64bit {
        return None;
    }

    let get_process_heap = find_import_rva(imports, "GetProcessHeap");
    let heap_alloc = find_import_rva(imports, "HeapAlloc");
    let heap_bootstrap = detect_heap_bootstrap(pe, dump_buf, imports);
    // Prefer pre-overlay cookie RVA; fall back to scanning current buffer.
    let cookie_rva = cookie_rva.or_else(|| find_security_cookie_rva(pe, dump_buf));

    let needs_restore = !containers.is_empty() || !heap_globals.is_empty();
    if needs_restore {
        match restore_mode {
            ContainerRestoreMode::Off => {
                warn!(
                    containers = containers.len(),
                    heap_globals = heap_globals.len(),
                    "Container/heap-global restore disabled"
                );
                return None;
            }
            ContainerRestoreMode::PostCrt => {
                let (Some(gph), Some(ha)) = (get_process_heap, heap_alloc) else {
                    warn!("Container restore needs GetProcessHeap + HeapAlloc imports");
                    return None;
                };
                // Never write CRT heap global from this stub (stdio poison).
                return super::container_bootstrap::install_post_crt_container_restore(
                    pe,
                    dump_buf,
                    containers,
                    heap_globals,
                    gph,
                    ha,
                    original_entry_point,
                    cookie_rva,
                    None, // do not refresh CRT heap global pre-stdio
                    cookie_mirror,
                );
            }
            ContainerRestoreMode::PreCrt => {
                warn!(
                    containers = containers.len(),
                    heap_globals = heap_globals.len(),
                    "Installing PRE-CRT container bootstrap (experimental; may break MSVC stdio)"
                );
                let (Some(gph), Some(ha)) = (get_process_heap, heap_alloc) else {
                    return None;
                };
                return super::container_bootstrap::install_container_bootstrap(
                    pe,
                    containers,
                    heap_globals,
                    gph,
                    ha,
                    original_entry_point,
                    pe.nt_headers.optional_header.image_base,
                    cookie_rva,
                    // Pre-CRT: still avoid writing CRT heap global.
                    None,
                    cookie_mirror,
                );
            }
        }
    }

    // No containers / heap globals: optional simple EP heap bootstrap for non-CRT.
    // Skip when EP looks like MSVC CRT wrapper — CRT must own heap globals.
    if is_crt_entry_wrapper(dump_buf, original_entry_point) {
        info!(
            entry = format_args!("{original_entry_point:#x}"),
            "Skipping simple heap EP bootstrap (CRT entry must re-init itself)"
        );
        return None;
    }

    let bootstrap = heap_bootstrap?;

    let section_idx = pe.create_section_index(".boot", 0x200);
    let stub_rva = pe.sections[section_idx].virtual_address;
    let stub = match build_stub(stub_rva, original_entry_point, bootstrap) {
        Some(stub) => stub,
        None => {
            pe.sections.remove(section_idx);
            pe.nt_headers.optional_header.size_of_image = pe
                .sections
                .last()
                .map(|section| {
                    crate::utils::align_up(
                        section.virtual_address.saturating_add(section.virtual_size),
                        pe.nt_headers.optional_header.section_alignment,
                    )
                })
                .unwrap_or(pe.nt_headers.optional_header.size_of_headers);
            warn!("Heap bootstrap targets are outside the x64 relative-address range");
            return None;
        }
    };

    let section = &mut pe.sections[section_idx];
    section.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    section.header.characteristics = section.characteristics;
    section.header.virtual_size = 0x200;
    section.virtual_size = 0x200;
    section.header.size_of_raw_data = 0x200;
    section.raw_size = 0x200;
    section.extra_data = Some(stub);

    info!(
        stub_rva = format_args!("{stub_rva:#x}"),
        heap_global_rva = format_args!("{:#x}", bootstrap.heap_global_rva),
        get_process_heap_iat_rva = format_args!("{:#x}", bootstrap.get_process_heap_iat_rva),
        original_entry_point = format_args!("{original_entry_point:#x}"),
        "Installed pre-OEP process heap bootstrap"
    );

    Some(stub_rva)
}

/// MSVC x64 default SecurityCookie. `__security_init_cookie` only regenerates
/// when the storage still equals this sentinel; early `.data` overlay zeros it
/// and leaves the dumped PE stuck with cookie=0 (encode becomes identity, GS fails).
pub(crate) const DEFAULT_SECURITY_COOKIE: u64 = 0x0000_2B99_2DDF_A232;

/// Cookie + complement RVAs captured from the live late image / offline CRT resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecurityCookieSite {
    pub cookie_rva: u32,
    pub complement_rva: u32,
}

/// Locate SecurityCookie + complement pair; return cookie RVA.
pub(crate) fn find_security_cookie_rva_public(pe: &PeHeader, dump_buf: &[u8]) -> Option<u32> {
    find_security_cookie_site(pe, dump_buf).map(|s| s.cookie_rva)
}

/// Locate cookie + complement RVAs before early overlay zeros them.
///
/// Fallback only — prefer [`resolve_security_cookie_site`] with authoritative RVAs.
pub(crate) fn find_security_cookie_site_public(
    pe: &PeHeader,
    dump_buf: &[u8],
) -> Option<SecurityCookieSite> {
    find_security_cookie_site(pe, dump_buf)
}

/// Prefer authoritative cookie site from offline CRT resolve; never rescan when present.
///
/// Authority is atomic (B7.2.1):
/// - `(None, None)` — legacy unique fallback scan only.
/// - `(Some, Some)` — validate and use that pair; invalid is a hard error (no rescan).
/// - `(Some, None)` / `(None, Some)` — hard error (half-authority forbidden).
///
/// Fallback scanner is section-name-independent (R+W non-X). Multiple distinct
/// cookie RVAs (including multiple DEFAULT pairs) fail closed — no "first pair".
pub(crate) fn resolve_security_cookie_site(
    pe: &PeHeader,
    dump_buf: &[u8],
    authoritative_cookie_rva: Option<u32>,
    authoritative_complement_rva: Option<u32>,
) -> Result<Option<SecurityCookieSite>, crate::error::PeError> {
    match (authoritative_cookie_rva, authoritative_complement_rva) {
        (None, None) => Ok(find_security_cookie_site(pe, dump_buf)),
        (Some(cookie_rva), Some(complement_rva)) => {
            let authoritative = SecurityCookieSite {
                cookie_rva,
                complement_rva,
            };
            if !authoritative_cookie_site_valid(pe, dump_buf.len(), authoritative) {
                return Err(crate::error::PeError::Parse(format!(
                    "Invalid authoritative SecurityCookie site \
                     (cookie_rva={cookie_rva:#x}, complement_rva={complement_rva:#x}); \
                     no rescan fallback"
                )));
            }
            info!(
                cookie_rva = format_args!("{cookie_rva:#x}"),
                complement_rva = format_args!("{complement_rva:#x}"),
                "Using authoritative SecurityCookie site (no rescan)"
            );
            Ok(Some(authoritative))
        }
        (Some(cookie_rva), None) => Err(crate::error::PeError::Parse(format!(
            "Partial SecurityCookie authority: cookie_rva={cookie_rva:#x} without complement; \
             no rescan fallback"
        ))),
        (None, Some(complement_rva)) => Err(crate::error::PeError::Parse(format!(
            "Partial SecurityCookie authority: complement_rva={complement_rva:#x} without cookie; \
             no rescan fallback"
        ))),
    }
}

fn authoritative_cookie_site_valid(
    pe: &PeHeader,
    dump_len: usize,
    site: SecurityCookieSite,
) -> bool {
    if site.cookie_rva == 0 || site.complement_rva == 0 || site.cookie_rva == site.complement_rva {
        return false;
    }
    let in_dump = |rva: u32| {
        (rva as usize)
            .checked_add(8)
            .is_some_and(|end| end <= dump_len)
    };
    if !in_dump(site.cookie_rva) || !in_dump(site.complement_rva) {
        return false;
    }
    pe.sections.iter().any(|section| {
        let chars = section.characteristics;
        chars & IMAGE_SCN_MEM_READ != 0
            && chars & IMAGE_SCN_MEM_WRITE != 0
            && chars & IMAGE_SCN_MEM_EXECUTE == 0
            && rva_range_in_section(
                site.cookie_rva,
                8,
                section.virtual_address,
                section.virtual_size,
            )
            && rva_range_in_section(
                site.complement_rva,
                8,
                section.virtual_address,
                section.virtual_size,
            )
    })
}

fn rva_range_in_section(rva: u32, len: u32, section_rva: u32, section_size: u32) -> bool {
    let Some(end) = rva.checked_add(len) else {
        return false;
    };
    let Some(section_end) = section_rva.checked_add(section_size) else {
        return false;
    };
    section_size != 0 && rva >= section_rva && end <= section_end
}

/// After early overlay / pointer scrub, re-plant the MSVC default cookie pair so
/// CRT re-entry runs `__security_init_cookie` regeneration.
///
/// When `site` is `Some`, plant **only** that site (no rescan). When `None`,
/// fall back to the unique-scan locator. Returns `false` if plant fails.
///
/// **Complement plant rule (Origin W1 / R-LOAD-FLAKE):** MSVC stores
/// `__security_cookie_complement` adjacent to the cookie (±8). A distant QWORD
/// that happens to equal `!cookie` (Origin: RVA `0xfc388` == `!DEFAULT` while
/// cookie is at `0xfc050`) is application data — planting there reintroduces
/// the AV object-head (`xchg [r10]` at o+0x39e5c). Non-adjacent complements are
/// rewritten to `cookie_rva + 8` before plant.
pub(crate) fn plant_default_security_cookie(
    pe: &PeHeader,
    dump_buf: &mut [u8],
    site: Option<SecurityCookieSite>,
) -> bool {
    // Authoritative `Some` must not rescan; only `None` may use legacy locate.
    let Some(site) = site.or_else(|| find_security_cookie_site(pe, dump_buf)) else {
        // Overlay may have wiped the live pair; try default layout scan fails.
        return false;
    };
    let site = normalize_cookie_site_for_plant(site);
    if !write_u64_at_rva(dump_buf, site.cookie_rva, DEFAULT_SECURITY_COOKIE) {
        return false;
    }
    if !write_u64_at_rva(dump_buf, site.complement_rva, !DEFAULT_SECURITY_COOKIE) {
        return false;
    }
    info!(
        cookie_rva = format_args!("{:#x}", site.cookie_rva),
        complement_rva = format_args!("{:#x}", site.complement_rva),
        cookie = format_args!("{DEFAULT_SECURITY_COOKIE:#x}"),
        "Planted MSVC default SecurityCookie for CRT re-init"
    );
    true
}

/// Force MSVC-adjacent complement for plant when the resolved site is distant.
fn normalize_cookie_site_for_plant(site: SecurityCookieSite) -> SecurityCookieSite {
    let dist = site.cookie_rva.abs_diff(site.complement_rva);
    if dist == 8 {
        return site;
    }
    let fixed = SecurityCookieSite {
        cookie_rva: site.cookie_rva,
        complement_rva: site.cookie_rva.saturating_add(8),
    };
    warn!(
        cookie_rva = format_args!("{:#x}", site.cookie_rva),
        rejected_complement_rva = format_args!("{:#x}", site.complement_rva),
        plant_complement_rva = format_args!("{:#x}", fixed.complement_rva),
        dist,
        "SecurityCookie complement not adjacent (±8); planting at cookie+8 (MSVC layout)"
    );
    fixed
}

fn find_security_cookie_rva(pe: &PeHeader, dump_buf: &[u8]) -> Option<u32> {
    find_security_cookie_site(pe, dump_buf).map(|s| s.cookie_rva)
}

/// R4-A3: when full RW scan is ambiguous, recover a unique site from a known
/// live cookie **value** (e.g. from detected SecurityCookie-encoded containers).
///
/// Strategy (fail-closed):
/// 1. Prefer **adjacent** cookie/complement pairs in `.data` / `.data*` only
///    (MSVC storage layout). Unique adjacent pair wins.
/// 2. Else unique cookie RVA in `.data` with any complement in that section.
/// 3. Else refuse (heap-rich dumps often copy the cookie value widely).
pub(crate) fn find_security_cookie_site_for_value(
    pe: &PeHeader,
    dump_buf: &[u8],
    cookie: u64,
) -> Option<SecurityCookieSite> {
    if !is_plausible_cookie(cookie) {
        return None;
    }
    let want = !cookie;
    let mut adjacent: Vec<SecurityCookieSite> = Vec::new();
    let mut data_cookie_hits: Vec<u32> = Vec::new();
    let mut data_complement_hits: Vec<u32> = Vec::new();

    for section in pe.sections.iter().filter(|s| {
        let chars = s.characteristics;
        chars & IMAGE_SCN_MEM_READ != 0
            && chars & IMAGE_SCN_MEM_WRITE != 0
            && chars & IMAGE_SCN_MEM_EXECUTE == 0
            && (s.name == ".data" || s.name.starts_with(".data"))
    }) {
        let start = section.virtual_address as usize;
        let Some(end) = start.checked_add(section.virtual_size as usize) else {
            continue;
        };
        let Some(slice) = dump_buf.get(start..end) else {
            continue;
        };
        if slice.len() < 8 {
            continue;
        }
        for offset in (0..=slice.len().saturating_sub(8)).step_by(8) {
            let v = u64::from_le_bytes(slice[offset..offset + 8].try_into().ok()?);
            let rva = section.virtual_address + offset as u32;
            if v == cookie {
                data_cookie_hits.push(rva);
                // Adjacent complement at +8 or -8 (MSVC typical).
                if offset + 16 <= slice.len() {
                    let next =
                        u64::from_le_bytes(slice[offset + 8..offset + 16].try_into().ok()?);
                    if next == want {
                        adjacent.push(SecurityCookieSite {
                            cookie_rva: rva,
                            complement_rva: rva + 8,
                        });
                    }
                }
                if offset >= 8 {
                    let prev =
                        u64::from_le_bytes(slice[offset - 8..offset].try_into().ok()?);
                    if prev == want {
                        adjacent.push(SecurityCookieSite {
                            cookie_rva: rva,
                            complement_rva: rva - 8,
                        });
                    }
                }
            } else if v == want {
                data_complement_hits.push(rva);
            }
        }
    }

    // Dedup adjacent by cookie_rva.
    if !adjacent.is_empty() {
        adjacent.sort_by_key(|s| s.cookie_rva);
        adjacent.dedup_by_key(|s| s.cookie_rva);
        if adjacent.len() == 1 {
            let site = adjacent[0];
            info!(
                cookie_rva = format_args!("{:#x}", site.cookie_rva),
                complement_rva = format_args!("{:#x}", site.complement_rva),
                cookie = format_args!("{cookie:#x}"),
                "Recovered SecurityCookie site from adjacent .data pair (container cookie)"
            );
            return Some(site);
        }
        warn!(
            cookie = format_args!("{cookie:#x}"),
            adjacent_pairs = adjacent.len(),
            "SecurityCookie value recovery fail-closed (multiple adjacent .data pairs)"
        );
        return None;
    }

    if data_cookie_hits.len() == 1 && !data_complement_hits.is_empty() {
        let cookie_rva = data_cookie_hits[0];
        let mut comps = data_complement_hits.clone();
        comps.sort_by_key(|r| r.abs_diff(cookie_rva));
        let complement_rva = comps[0];
        if complement_rva != cookie_rva {
            info!(
                cookie_rva = format_args!("{cookie_rva:#x}"),
                complement_rva = format_args!("{complement_rva:#x}"),
                cookie = format_args!("{cookie:#x}"),
                "Recovered SecurityCookie site from unique .data cookie value"
            );
            return Some(SecurityCookieSite {
                cookie_rva,
                complement_rva,
            });
        }
    }

    warn!(
        cookie = format_args!("{cookie:#x}"),
        data_cookie_rvas = data_cookie_hits.len(),
        data_complement_rvas = data_complement_hits.len(),
        adjacent_pairs = 0,
        "SecurityCookie value recovery fail-closed (no unique .data pair)"
    );
    None
}

/// Unique cookie value across container snapshots, if any.
pub(crate) fn unique_container_cookie(containers: &[ContainerSnapshot]) -> Option<u64> {
    let mut values: Vec<u64> = containers.iter().map(|c| c.cookie).collect();
    values.sort_unstable();
    values.dedup();
    if values.len() == 1 && is_plausible_cookie(values[0]) {
        Some(values[0])
    } else {
        None
    }
}

/// Fallback: scan all readable+writable non-executable sections for a unique
/// cookie/complement pair. Section names are ignored (B6 has blank-name RW).
///
/// Fail-closed when multiple distinct cookie RVAs exist — including multiple
/// DEFAULT sentinel pairs. Never picks the first default pair on ambiguity.
fn find_security_cookie_site(pe: &PeHeader, dump_buf: &[u8]) -> Option<SecurityCookieSite> {
    let mut all_pairs: Vec<SecurityCookieSite> = Vec::new();

    for section in pe.sections.iter() {
        let chars = section.characteristics;
        let readable = chars & IMAGE_SCN_MEM_READ != 0;
        let writable = chars & IMAGE_SCN_MEM_WRITE != 0;
        let executable = chars & IMAGE_SCN_MEM_EXECUTE != 0;
        if !readable || !writable || executable {
            continue;
        }
        let start = section.virtual_address as usize;
        let Some(end) = start.checked_add(section.virtual_size as usize) else {
            continue;
        };
        let slice = match dump_buf.get(start..end) {
            Some(s) if s.len() >= 16 => s,
            _ => continue,
        };

        let mut cookies: Vec<(usize, u64)> = Vec::new();
        for offset in (0..=slice.len().saturating_sub(8)).step_by(8) {
            let v = u64::from_le_bytes(slice[offset..offset + 8].try_into().ok()?);
            if is_plausible_cookie(v) {
                cookies.push((offset, v));
            }
        }
        for &(c_off, c_val) in &cookies {
            let want = !c_val;
            for offset in (0..=slice.len().saturating_sub(8)).step_by(8) {
                if offset == c_off {
                    continue;
                }
                let v = u64::from_le_bytes(slice[offset..offset + 8].try_into().ok()?);
                if v == want {
                    all_pairs.push(SecurityCookieSite {
                        cookie_rva: section.virtual_address + c_off as u32,
                        complement_rva: section.virtual_address + offset as u32,
                    });
                }
            }
        }
    }

    if all_pairs.is_empty() {
        return None;
    }

    // Prefer DEFAULT sentinel only when it yields a unique cookie RVA.
    let default_pairs: Vec<_> = all_pairs
        .iter()
        .copied()
        .filter(|p| {
            let off = p.cookie_rva as usize;
            dump_buf
                .get(off..off + 8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
                == Some(DEFAULT_SECURITY_COOKIE)
        })
        .collect();

    let candidate_pool = if !default_pairs.is_empty() {
        default_pairs
    } else {
        all_pairs
    };

    let mut cookie_rvas: Vec<u32> = candidate_pool.iter().map(|p| p.cookie_rva).collect();
    cookie_rvas.sort_unstable();
    cookie_rvas.dedup();
    // B7.2: multiple different cookie RVAs → ambiguity fail-closed.
    // Do NOT select the first default pair.
    if cookie_rvas.len() != 1 {
        warn!(
            distinct_cookie_rvas = cookie_rvas.len(),
            "SecurityCookie scan ambiguous — fail-closed (no first-pair pick)"
        );
        return None;
    }
    let cookie_rva = cookie_rvas[0];
    let mut same: Vec<_> = candidate_pool
        .into_iter()
        .filter(|p| p.cookie_rva == cookie_rva)
        .collect();
    // Prefer true MSVC adjacent complement (±8) over distant !cookie collisions
    // (Origin app object head at 0xfc388 equals !DEFAULT while cookie is 0xfc050).
    let mut adjacent: Vec<_> = same
        .iter()
        .copied()
        .filter(|p| p.complement_rva.abs_diff(p.cookie_rva) == 8)
        .collect();
    if !adjacent.is_empty() {
        adjacent.sort_by_key(|p| p.complement_rva);
        return Some(adjacent[0]);
    }
    same.sort_by_key(|p| p.complement_rva.abs_diff(p.cookie_rva));
    Some(same[0])
}

fn write_u64_at_rva(dump_buf: &mut [u8], rva: u32, value: u64) -> bool {
    let start = rva as usize;
    let end = start.saturating_add(8);
    if end > dump_buf.len() {
        return false;
    }
    dump_buf[start..end].copy_from_slice(&value.to_le_bytes());
    true
}

fn is_plausible_cookie(value: u64) -> bool {
    value != 0 && value != u64::MAX && value <= 0x0000_ffff_ffff_ffff
}

#[cfg(test)]
mod cookie_tests {
    use super::*;

    #[test]
    fn recovers_site_from_known_cookie_value_in_data() {
        // Adjacent cookie+complement in .data; extra cookie copies elsewhere ignored.
        let mut buf = vec![0u8; 0x200];
        let cookie: u64 = 0x0000_1234_5678_9abc;
        // Stray cookie value at 0x20 without adjacent complement (must not match alone).
        buf[0x20..0x28].copy_from_slice(&cookie.to_le_bytes());
        // Real adjacent pair at 0x100 / 0x108.
        buf[0x100..0x108].copy_from_slice(&cookie.to_le_bytes());
        buf[0x108..0x110].copy_from_slice(&(!cookie).to_le_bytes());

        let pe = pe_with_named_rw_section(".data", 0, 0x200, 0xC000_0040);
        let site = find_security_cookie_site_for_value(&pe, &buf, cookie).expect("recover");
        assert_eq!(site.cookie_rva, 0x100);
        assert_eq!(site.complement_rva, 0x108);
    }

    #[test]
    fn recovery_ignores_cookie_copies_outside_data() {
        let mut buf = vec![0u8; 0x300];
        let cookie: u64 = 0x0000_aaaa_bbbb_cccc;
        // .data-only pe: adjacent pair unique.
        buf[0x40..0x48].copy_from_slice(&cookie.to_le_bytes());
        buf[0x48..0x50].copy_from_slice(&(!cookie).to_le_bytes());
        let pe = pe_with_named_rw_section(".data", 0, 0x100, 0xC000_0040);
        let site = find_security_cookie_site_for_value(&pe, &buf, cookie).expect("adjacent");
        assert_eq!(site.cookie_rva, 0x40);
    }

    #[test]
    fn unique_container_cookie_requires_single_value() {
        let a = ContainerSnapshot {
            rva: 0x10,
            decoded_begin: 0x10000,
            decoded_end: 0x10100,
            decoded_capacity: 0x10200,
            cookie: 0xabc,
            heap_content: vec![0; 4],
        };
        let mut b = a.clone();
        b.cookie = 0xdef;
        assert_eq!(unique_container_cookie(&[a.clone()]), Some(0xabc));
        assert_eq!(unique_container_cookie(&[a, b]), None);
    }

    #[test]
    fn plants_default_cookie_at_captured_site() {
        let cookie: u64 = 0x3497_64dd_2eee;
        let mut buf = vec![0u8; 0x40];
        // Fake .data layout at RVA 0x10: cookie then complement
        buf[0x10..0x18].copy_from_slice(&cookie.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&(!cookie).to_le_bytes());
        // Zero as early overlay would
        buf[0x10..0x20].fill(0);

        let site = SecurityCookieSite {
            cookie_rva: 0x10,
            complement_rva: 0x18,
        };
        assert!(plant_default_security_cookie_direct(&mut buf, site));
        let planted = u64::from_le_bytes(buf[0x10..0x18].try_into().unwrap());
        let complement = u64::from_le_bytes(buf[0x18..0x20].try_into().unwrap());
        assert_eq!(planted, DEFAULT_SECURITY_COOKIE);
        assert_eq!(complement, !DEFAULT_SECURITY_COOKIE);
    }

    #[test]
    fn nonadjacent_cookie_site_reaches_dumper_plant() {
        // B6 layout: cookie @ +0x80, complement @ +0xC0 (gap 0x40, not adjacent).
        let mut buf = vec![0u8; 0x100];
        let cookie_off = 0x80usize;
        let comp_off = 0xC0usize;
        buf[cookie_off..cookie_off + 8].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        buf[comp_off..comp_off + 8].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());
        // Simulate early overlay zeroing both slots.
        buf[cookie_off..cookie_off + 8].fill(0);
        buf[comp_off..comp_off + 8].fill(0);

        let site = SecurityCookieSite {
            cookie_rva: cookie_off as u32,
            complement_rva: comp_off as u32,
        };
        assert_ne!(site.complement_rva, site.cookie_rva.wrapping_add(8));
        assert!(plant_default_security_cookie_direct(&mut buf, site));
        let planted = u64::from_le_bytes(buf[cookie_off..cookie_off + 8].try_into().unwrap());
        let complement = u64::from_le_bytes(buf[comp_off..comp_off + 8].try_into().unwrap());
        assert_eq!(planted, DEFAULT_SECURITY_COOKIE);
        assert_eq!(complement, !DEFAULT_SECURITY_COOKIE);
    }

    fn plant_default_security_cookie_direct(dump_buf: &mut [u8], site: SecurityCookieSite) -> bool {
        if !write_u64_at_rva(dump_buf, site.cookie_rva, DEFAULT_SECURITY_COOKIE) {
            return false;
        }
        write_u64_at_rva(dump_buf, site.complement_rva, !DEFAULT_SECURITY_COOKIE)
    }

    fn pe_with_named_rw_section(name: &str, va: u32, vsize: u32, chars: u32) -> PeHeader {
        let mut pe = pe_with_rw_section(va, vsize, chars);
        pe.sections[0].name = name.to_string();
        pe
    }

    /// Minimal PE with blank-name R+W section (B6-like) for cookie scan tests.
    fn pe_with_rw_section(va: u32, vsize: u32, chars: u32) -> PeHeader {
        use crate::header::{
            ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders,
            ImageOptionalHeader, ImageSectionHeader, PeSection,
        };
        PeHeader {
            dos_header: ImageDosHeader {
                e_magic: 0x5A4D,
                e_lfanew: 0x80,
            },
            nt_headers: ImageNtHeaders {
                signature: 0x4550,
                file_header: ImageFileHeader {
                    machine: 0x8664,
                    number_of_sections: 1,
                    time_date_stamp: 0,
                    size_of_optional_header: 0xF0,
                    characteristics: 0x22,
                },
                optional_header: ImageOptionalHeader {
                    magic: 0x20B,
                    major_linker_version: 14,
                    minor_linker_version: 0,
                    size_of_code: 0,
                    size_of_initialized_data: vsize,
                    size_of_uninitialized_data: 0,
                    address_of_entry_point: 0x1000,
                    base_of_code: 0x1000,
                    base_of_data: None,
                    image_base: 0x140000000,
                    section_alignment: 0x1000,
                    file_alignment: 0x200,
                    major_operating_system_version: 6,
                    minor_operating_system_version: 0,
                    major_image_version: 0,
                    minor_image_version: 0,
                    major_subsystem_version: 6,
                    minor_subsystem_version: 0,
                    win32_version_value: 0,
                    size_of_image: va + vsize + 0x1000,
                    size_of_headers: 0x400,
                    check_sum: 0,
                    subsystem: 3,
                    dll_characteristics: 0,
                    size_of_stack_reserve: 0x100000,
                    size_of_stack_commit: 0x1000,
                    size_of_heap_reserve: 0x100000,
                    size_of_heap_commit: 0x1000,
                    loader_flags: 0,
                    number_of_rva_and_sizes: 16,
                    data_directory: [ImageDataDirectory::default(); 16],
                },
            },
            sections: vec![PeSection {
                header: ImageSectionHeader {
                    name: [0u8; 8],
                    virtual_size: vsize,
                    virtual_address: va,
                    size_of_raw_data: vsize,
                    pointer_to_raw_data: va,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: chars,
                },
                name: String::new(),
                virtual_address: va,
                virtual_size: vsize,
                raw_offset: va,
                raw_size: vsize,
                characteristics: chars,
                extra_data: None,
            }],
            image_base: 0x140000000,
            entry_point: 0x1000,
            is_64bit: true,
            file_alignment: 0x200,
            section_alignment: 0x1000,
        }
    }

    #[test]
    fn multiple_default_cookie_rvas_fail_closed() {
        // Two DEFAULT pairs at different RVAs in the same blank-name RW section.
        let va = 0x1000u32;
        let chars = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40;
        let pe = pe_with_rw_section(va, 0x200, chars);
        let mut buf = vec![0u8; 0x1200];
        let c1 = 0x1080usize;
        let p1 = 0x10C0usize;
        let c2 = 0x1100usize;
        let p2 = 0x1140usize;
        buf[c1..c1 + 8].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        buf[p1..p1 + 8].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());
        buf[c2..c2 + 8].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        buf[p2..p2 + 8].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());

        // Must NOT pick the first default pair.
        assert!(
            find_security_cookie_site(&pe, &buf).is_none(),
            "multiple distinct DEFAULT cookie RVAs must fail closed"
        );
    }

    #[test]
    fn dumper_does_not_rescan_when_authoritative_site_present() {
        // Empty dump (scan would find nothing) but authoritative site wins.
        let pe = pe_with_rw_section(
            0x1000,
            0x100,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
        );
        let mut buf = vec![0u8; 0x2000];
        let auth = SecurityCookieSite {
            cookie_rva: 0x1080,
            complement_rva: 0x10C0,
        };
        let site = resolve_security_cookie_site(
            &pe,
            &buf,
            Some(auth.cookie_rva),
            Some(auth.complement_rva),
        )
        .expect("authoritative site must be used without rescan")
        .expect("Some(site)");
        assert_eq!(site, auth);
        // Fallback scan alone fails on empty buffer.
        assert!(find_security_cookie_site(&pe, &buf).is_none());
        // Plant still works from authoritative site.
        assert!(plant_default_security_cookie(&pe, &mut buf, Some(auth)));
        let planted = u64::from_le_bytes(buf[0x1080..0x1088].try_into().unwrap());
        assert_eq!(planted, DEFAULT_SECURITY_COOKIE);
    }

    #[test]
    fn xref_cookie_site_propagates_to_dump_process() {
        // Simulates DumpOptions authoritative fields → resolve_security_cookie_site.
        let pe = pe_with_rw_section(
            0x1F3000,
            0xA5CC,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
        );
        let buf = vec![0u8; 0x200000]; // zeros — scan fails
        let cookie_rva = 0x1F6F80u32;
        let complement_rva = 0x1F6FC0u32;
        let site = resolve_security_cookie_site(&pe, &buf, Some(cookie_rva), Some(complement_rva))
            .unwrap()
            .unwrap();
        assert_eq!(site.cookie_rva, cookie_rva);
        assert_eq!(site.complement_rva, complement_rva);
        // Without authority, empty image fails closed (no false first-pair).
        assert!(find_security_cookie_site(&pe, &buf).is_none());
    }

    #[test]
    fn blank_name_rw_section_scanned_without_dot_data() {
        let va = 0x1F3000u32;
        let pe = pe_with_rw_section(va, 0x200, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40);
        assert!(pe
            .sections
            .iter()
            .all(|s| s.name.is_empty() || s.name != ".data"));
        let mut buf = vec![0u8; 0x1F3200];
        let c_off = 0x1F6F80usize; // outside this tiny section — use in-section
        let cookie_off = (va + 0x80) as usize;
        let comp_off = (va + 0xC0) as usize;
        buf[cookie_off..cookie_off + 8].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        buf[comp_off..comp_off + 8].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());
        let site = find_security_cookie_site(&pe, &buf).expect("blank-name RW must be scanned");
        assert_eq!(site.cookie_rva, va + 0x80);
        assert_eq!(site.complement_rva, va + 0xC0);
        let _ = c_off;
    }

    // -----------------------------------------------------------------------
    // B7.2.1 — atomic authority, no half-state fallback
    // -----------------------------------------------------------------------

    #[test]
    fn cookie_only_authority_rejected_without_rescan() {
        let pe = pe_with_rw_section(
            0x1000,
            0x200,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
        );
        // Unique fallback pair exists — must NOT be used when only cookie is set.
        let mut buf = vec![0u8; 0x2000];
        buf[0x1080..0x1088].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        buf[0x10C0..0x10C8].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());
        assert!(find_security_cookie_site(&pe, &buf).is_some());

        let err = resolve_security_cookie_site(&pe, &buf, Some(0x1080), None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Partial") || msg.contains("without complement"),
            "cookie-only must hard-error without rescan: {msg}"
        );
    }

    #[test]
    fn complement_only_authority_rejected_without_rescan() {
        let pe = pe_with_rw_section(
            0x1000,
            0x200,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
        );
        let mut buf = vec![0u8; 0x2000];
        buf[0x1080..0x1088].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        buf[0x10C0..0x10C8].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());
        assert!(find_security_cookie_site(&pe, &buf).is_some());

        let err = resolve_security_cookie_site(&pe, &buf, None, Some(0x10C0)).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Partial") || msg.contains("without cookie"),
            "complement-only must hard-error without rescan: {msg}"
        );
    }

    #[test]
    fn invalid_authority_rejected_without_rescan() {
        let pe = pe_with_rw_section(
            0x1000,
            0x100,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
        );
        // Valid unique fallback pair at a different site.
        let mut buf = vec![0u8; 0x2000];
        buf[0x1080..0x1088].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        buf[0x10C0..0x10C8].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());
        assert!(find_security_cookie_site(&pe, &buf).is_some());

        // Authority points outside the RW section (invalid) — must not fall back.
        let err = resolve_security_cookie_site(&pe, &buf, Some(0x2000), Some(0x2008)).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Invalid authoritative") || msg.contains("no rescan"),
            "invalid pair must hard-error without rescan: {msg}"
        );
    }

    #[test]
    fn invalid_authority_propagates_from_dump_process() {
        // Contract surface: dump_process uses `?` on resolve — same error path.
        // Unit-level: resolve returns PeError that dump_process would propagate.
        let pe = pe_with_rw_section(
            0x1000,
            0x100,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
        );
        let buf = vec![0u8; 0x2000];
        let err = resolve_security_cookie_site(&pe, &buf, Some(0x1080), None);
        assert!(
            err.is_err(),
            "half-authority must be Err for dump_process `?`"
        );
        let err2 = resolve_security_cookie_site(&pe, &buf, Some(0x50), Some(0x58));
        assert!(
            err2.is_err(),
            "out-of-section authority must be Err for dump_process `?`"
        );
        // Plant failure with authority present must be treated as hard error by dump_process.
        // Simulate: resolve succeeds, then plant write out of dump_buf fails.
        let pe2 = pe_with_rw_section(
            0x1000,
            0x100,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
        );
        // dump_buf shorter than site end → plant fails
        let mut short = vec![0u8; 0x1080 + 4];
        let auth = SecurityCookieSite {
            cookie_rva: 0x1080,
            complement_rva: 0x10C0,
        };
        // Authority valid against pe+len would fail — use full buf for resolve, short for plant.
        let full = vec![0u8; 0x2000];
        let site = resolve_security_cookie_site(
            &pe2,
            &full,
            Some(auth.cookie_rva),
            Some(auth.complement_rva),
        )
        .unwrap()
        .unwrap();
        assert!(!plant_default_security_cookie(&pe2, &mut short, Some(site)));
    }

    #[test]
    fn valid_authority_never_rescans() {
        let pe = pe_with_rw_section(
            0x1000,
            0x200,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
        );
        let mut buf = vec![0u8; 0x2000];
        // Tempting fallback pair at 0x1080/0x10C0
        buf[0x1080..0x1088].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        buf[0x10C0..0x10C8].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());
        // Authority at different valid site (empty slots, still structural-valid).
        let auth_c = 0x1100u32;
        let auth_p = 0x1140u32;
        let site = resolve_security_cookie_site(&pe, &buf, Some(auth_c), Some(auth_p))
            .expect("valid authority")
            .expect("Some");
        assert_eq!(site.cookie_rva, auth_c);
        assert_eq!(site.complement_rva, auth_p);
        // Must not silently pick the tempting DEFAULT pair.
        assert_ne!(site.cookie_rva, 0x1080);
    }

    #[test]
    fn no_authority_unique_fallback_still_supported() {
        let pe = pe_with_rw_section(
            0x1000,
            0x200,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
        );
        let mut buf = vec![0u8; 0x2000];
        buf[0x1080..0x1088].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        buf[0x10C0..0x10C8].copy_from_slice(&(!DEFAULT_SECURITY_COOKIE).to_le_bytes());
        let site = resolve_security_cookie_site(&pe, &buf, None, None)
            .expect("no-authority must not error")
            .expect("unique fallback");
        assert_eq!(site.cookie_rva, 0x1080);
        assert_eq!(site.complement_rva, 0x10C0);
    }
}

/// MSVC x64 PE entry: `sub rsp, 28h; call __security_init_cookie; add rsp,28h; jmp scrt`
fn is_crt_entry_wrapper(dump_buf: &[u8], ep_rva: u32) -> bool {
    let off = ep_rva as usize;
    let bytes = match dump_buf.get(off..off.saturating_add(16)) {
        Some(b) => b,
        None => return false,
    };
    bytes.len() >= 14
        && bytes[0..4] == [0x48, 0x83, 0xec, 0x28]
        && bytes[4] == 0xe8
        && bytes[9..13] == [0x48, 0x83, 0xc4, 0x28]
        && bytes[13] == 0xe9
}

fn detect_heap_bootstrap(
    pe: &PeHeader,
    dump_buf: &[u8],
    imports: &ImportTableBuilder,
) -> Option<HeapBootstrap> {
    let get_process_heap_iat_rva = find_import_rva(imports, "GetProcessHeap")?;
    let heap_api_slots: HashMap<u32, &str> = imports
        .modules
        .iter()
        .flat_map(|module| module.thunks.iter())
        .filter_map(|thunk| {
            let name = thunk.function_name.as_deref()?;
            HEAP_APIS
                .contains(&name)
                .then_some((thunk.iat_address, name))
        })
        .collect();
    if heap_api_slots.is_empty() {
        return None;
    }

    let mut evidence: HashMap<u32, HashSet<&str>> = HashMap::new();
    for section in pe
        .sections
        .iter()
        .filter(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
    {
        let start = section.virtual_address as usize;
        let end = start
            .saturating_add(section.virtual_size as usize)
            .min(dump_buf.len());
        let Some(code) = dump_buf.get(start..end) else {
            continue;
        };

        for call_offset in 0..=code.len().saturating_sub(6) {
            if code[call_offset] != 0xff || code[call_offset + 1] != 0x15 {
                continue;
            }
            let call_rva = section.virtual_address.saturating_add(call_offset as u32);
            let call_target =
                rip_relative_target(call_rva, 6, &code[call_offset + 2..call_offset + 6]);
            let Some(api_name) = call_target.and_then(|rva| heap_api_slots.get(&rva).copied())
            else {
                continue;
            };

            let search_start = call_offset.saturating_sub(MAX_LOAD_TO_CALL_DISTANCE);
            let load = (search_start..call_offset).rev().find(|&offset| {
                offset + 7 <= call_offset
                    && code[offset..offset + 3] == [0x48, 0x8b, 0x0d]
                    && !code[offset + 7..call_offset]
                        .windows(2)
                        .any(|bytes| bytes == [0xff, 0x15])
            });
            let Some(load_offset) = load else {
                continue;
            };
            let load_rva = section.virtual_address.saturating_add(load_offset as u32);
            let Some(global_rva) =
                rip_relative_target(load_rva, 7, &code[load_offset + 3..load_offset + 7])
            else {
                continue;
            };
            if is_stale_writable_global(pe, dump_buf, global_rva) {
                evidence.entry(global_rva).or_default().insert(api_name);
            }
        }
    }

    let (heap_global_rva, api_evidence) = evidence
        .into_iter()
        .max_by_key(|(_, api_evidence)| api_evidence.len())?;
    // One isolated call is too weak: require the same global to feed at least
    // two distinct heap operations before changing the executable entry point.
    if api_evidence.len() < 2 {
        return None;
    }

    Some(HeapBootstrap {
        heap_global_rva,
        get_process_heap_iat_rva,
    })
}

fn find_import_rva(imports: &ImportTableBuilder, wanted: &str) -> Option<u32> {
    imports
        .modules
        .iter()
        .flat_map(|module| module.thunks.iter())
        .find(|thunk| thunk.function_name.as_deref() == Some(wanted))
        .map(|thunk| thunk.iat_address)
}

fn rip_relative_target(
    instruction_rva: u32,
    instruction_len: u32,
    displacement: &[u8],
) -> Option<u32> {
    let bytes: [u8; 4] = displacement.try_into().ok()?;
    let next = i64::from(instruction_rva) + i64::from(instruction_len);
    u32::try_from(next + i64::from(i32::from_le_bytes(bytes))).ok()
}

fn is_stale_writable_global(pe: &PeHeader, dump_buf: &[u8], rva: u32) -> bool {
    // After early .data overlay reinitialization the CRT heap handle global is
    // often zeroed.  The previous filter required a non-zero stale handle and
    // therefore missed the exact global that must be refreshed before OEP.
    pe.sections.iter().any(|section| {
        let end = section
            .virtual_address
            .saturating_add(section.virtual_size.max(section.raw_size));
        section.characteristics & IMAGE_SCN_MEM_WRITE != 0
            && rva >= section.virtual_address
            && rva.saturating_add(8) <= end
            && dump_buf.get(rva as usize..rva as usize + 8).is_some()
    })
}

fn build_stub(
    stub_rva: u32,
    original_entry_point: u32,
    bootstrap: HeapBootstrap,
) -> Option<Vec<u8>> {
    let mut stub = Vec::with_capacity(0x200);
    stub.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]); // sub rsp, 28h

    stub.extend_from_slice(&[0xff, 0x15]); // call qword ptr [rip+disp32]
    let call_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(
        call_next,
        bootstrap.get_process_heap_iat_rva,
    )?);

    stub.extend_from_slice(&[0x48, 0x89, 0x05]); // mov qword ptr [rip+disp32], rax
    let store_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(
        store_next,
        bootstrap.heap_global_rva,
    )?);

    stub.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]); // add rsp, 28h
    stub.push(0xe9); // jmp rel32
    let jump_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(jump_next, original_entry_point)?);
    debug_assert_eq!(stub.len(), STUB_SIZE);
    stub.resize(0x200, 0xcc);
    Some(stub)
}

fn relative_displacement(next_rva: u32, target_rva: u32) -> Option<[u8; 4]> {
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    i32::try_from(displacement).ok().map(i32::to_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_targets_import_global_and_oep() {
        let bootstrap = HeapBootstrap {
            heap_global_rva: 0x145d50,
            get_process_heap_iat_rva: 0xfd480,
        };
        let stub = build_stub(0x200000, 0x1000, bootstrap).unwrap();

        assert_eq!(stub.len(), 0x200);
        assert_eq!(&stub[..4], &[0x48, 0x83, 0xec, 0x28]);
        assert_eq!(
            rip_relative_target(0x200004, 6, &stub[6..10]),
            Some(bootstrap.get_process_heap_iat_rva)
        );
        assert_eq!(
            rip_relative_target(0x20000a, 7, &stub[13..17]),
            Some(bootstrap.heap_global_rva)
        );
        assert_eq!(
            rip_relative_target(0x200015, 5, &stub[22..26]),
            Some(0x1000)
        );
    }

    #[test]
    fn rip_relative_target_sign_extends_negative_displacement() {
        assert_eq!(
            rip_relative_target(0x2000, 6, &(-0x1006i32).to_le_bytes()),
            Some(0x1000)
        );
    }

    #[test]
    fn zeroed_writable_global_is_accepted_after_overlay() {
        // Minimal synthetic image: one writable .data page, all zeros.
        // The detector must accept the zeroed CRT heap handle location after
        // early-section overlay, not require a live process handle value.
        let pe = PeHeader {
            dos_header: crate::header::ImageDosHeader {
                e_magic: 0x5a4d,
                e_lfanew: 0x80,
            },
            nt_headers: crate::header::ImageNtHeaders {
                signature: 0x4550,
                file_header: crate::header::ImageFileHeader {
                    machine: 0x8664,
                    number_of_sections: 1,
                    time_date_stamp: 0,
                    size_of_optional_header: 0xf0,
                    characteristics: 0x22,
                },
                optional_header: crate::header::ImageOptionalHeader {
                    magic: 0x20b,
                    major_linker_version: 14,
                    minor_linker_version: 0,
                    size_of_code: 0,
                    size_of_initialized_data: 0,
                    size_of_uninitialized_data: 0,
                    address_of_entry_point: 0x1000,
                    base_of_code: 0x1000,
                    base_of_data: None,
                    image_base: 0x140000000,
                    section_alignment: 0x1000,
                    file_alignment: 0x200,
                    major_operating_system_version: 6,
                    minor_operating_system_version: 0,
                    major_image_version: 0,
                    minor_image_version: 0,
                    major_subsystem_version: 6,
                    minor_subsystem_version: 0,
                    win32_version_value: 0,
                    size_of_image: 0x2000,
                    size_of_headers: 0x400,
                    check_sum: 0,
                    subsystem: 2,
                    dll_characteristics: 0,
                    size_of_stack_reserve: 0x100000,
                    size_of_stack_commit: 0x1000,
                    size_of_heap_reserve: 0x100000,
                    size_of_heap_commit: 0x1000,
                    loader_flags: 0,
                    number_of_rva_and_sizes: 16,
                    data_directory: [crate::header::ImageDataDirectory {
                        virtual_address: 0,
                        size: 0,
                    }; 16],
                },
            },
            sections: vec![crate::header::PeSection {
                header: crate::header::ImageSectionHeader {
                    name: *b".data\0\0\0",
                    virtual_size: 0x1000,
                    virtual_address: 0x1000,
                    size_of_raw_data: 0x1000,
                    pointer_to_raw_data: 0x400,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: IMAGE_SCN_MEM_WRITE,
                },
                name: ".data".into(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0x400,
                raw_size: 0x1000,
                characteristics: IMAGE_SCN_MEM_WRITE,
                extra_data: None,
            }],
            image_base: 0x140000000,
            entry_point: 0x1000,
            is_64bit: true,
            file_alignment: 0x200,
            section_alignment: 0x1000,
        };
        let dump = vec![0u8; 0x2000];
        assert!(is_stale_writable_global(&pe, &dump, 0x15d0));
    }
}
