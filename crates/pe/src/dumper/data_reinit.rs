//! Reset stale process-local containers captured in a dumped `.data` section.

use std::path::Path;

use tracing::{info, warn};

use crate::header::PeHeader;

const POINTER_TRIPLE_SIZE: usize = 24;
const MIN_USER_POINTER: u64 = 0x1_0000;
const MAX_USER_POINTER: u64 = 0x0000_7fff_ffff_ffff;
/// Absolute CRT/heap pointers observed in dumped Themida images land in the
/// low 4GB of the process (e.g. `0x8d3e40`, `0x8a0000`). In that band, only
/// 8-byte-aligned values are scrubbed so packed constants / cookie fragments
/// are not zeroed.
const MAX_LOW_HEAP_POINTER: u64 = 0x0000_0000_ffff_ffff;
/// Upper bound for process-local user pointers considered for scrubbing.
/// Mid-user heap slots above 4GB (e.g. Themida `0x2b99…`) are cleared even
/// when unaligned.
///
/// Do **not** scrub the high ASLR module band (`>= HIGH_ASLR_MODULE_MIN`):
/// late dumps still hold ASLR image VAs (`0x7ff7…`) for CRT function tables
/// until `fix_hardcoded_addresses` rebases them; clearing those zeros
/// `call [fn_table]` (Origin W1 live regression).
const MAX_PROCESS_LOCAL_HEAP_POINTER: u64 = 0x0000_7fff_ffff_fffe;
/// Typical x64 module / system image ASLR floor. Pointers in this band are
/// treated as rebase candidates, not process-local heap garbage.
const HIGH_ASLR_MODULE_MIN: u64 = 0x0000_7ff0_0000_0000;
/// Session module table shape: `(image name, base, end-exclusive)` captured
/// from the *dumped* process. The module snapshot skips the dumped image
/// itself, so a value landing inside one of these ranges is a stale
/// cross-module pointer of the old ASLR session (e.g. an ntdll/kernel32 base
/// that re-randomizes on every boot).
pub(crate) type SessionModuleRange = (String, u64, u64);
/// Kernel-half addresses (`>= 0xffff_8000_0000_0000`) seen in Origin dumps
/// (e.g. `.data+0xfc388 = 0xffffd466…` == `!DEFAULT_COOKIE` collision) are
/// never valid as re-entry object heads and must be cleared even when unaligned.
const KERNEL_CANONICAL_MIN: u64 = 0xffff_8000_0000_0000;
const MAX_CONTAINER_SPAN: u64 = 0x1000_0000;
pub(crate) const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub(crate) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Reset SecurityCookie-encoded `{begin, end, capacity}` triples whose decoded
/// pointers refer to process-local heap memory, and clear raw process-local
/// absolute pointers (CRT heap handles, `_pioinfo`, stdio tables, etc.).
///
/// Keeping those live-process addresses in an independent dump makes the CRT
/// re-entry path (e.g. `__scrt_common_main_seh`) dereference freed heap and
/// AV at `_pioinfo[i]->_ptr` / similar globals.
/// Re-initialize `RTL_CRITICAL_SECTION` objects at the given `.data` RVAs.
///
/// A captured CS carries stale/zero lock state from the dumped process:
/// `LockCount = 0` (not `-1`) makes `RtlEnterCriticalSection` treat the
/// section as contended and wait on a NULL `LockSemaphore`, AV-ing. We reset
/// to the unlocked state a fresh `InitializeCriticalSection` would produce:
/// `LockCount = -1`, `RecursionCount = 0`, `OwningThread = 0`,
/// `LockSemaphore = 0`, `SpinCount = 0` (leaving `DebugInfo` as-is; the
/// loader tolerates a zeroed CS without a live DebugInfo on re-entry).
///
/// R-GTO-UI round 5: validated by byte-patch (LockCount=-1 clears the
/// `RtlEnterCriticalSection` AV in the GTO WinMain path).
pub(crate) fn reinit_critical_sections(dump_buf: &mut [u8], cs_rvas: &[u32]) -> usize {
    let mut reinit = 0usize;
    for &rva in cs_rvas {
        let off = rva as usize;
        // RTL_CRITICAL_SECTION is 40 bytes on x64.
        if off.saturating_add(40) > dump_buf.len() {
            warn!(
                cs_rva = format_args!("{rva:#x}"),
                "CS re-init out of bounds"
            );
            continue;
        }
        // x64 RTL_CRITICAL_SECTION layout:
        // +0 DebugInfo, +8 LockCount (i32), +12 RecursionCount (i32),
        // +16 OwningThread (HANDLE/ptr), +24 LockSemaphore (HANDLE/ptr),
        // +32 SpinCount (usize).
        dump_buf[off + 8..off + 12].copy_from_slice(&(-1i32).to_le_bytes());
        dump_buf[off + 12..off + 16].copy_from_slice(&0i32.to_le_bytes());
        dump_buf[off + 16..off + 24].copy_from_slice(&0u64.to_le_bytes()); // OwningThread
        dump_buf[off + 24..off + 32].copy_from_slice(&0u64.to_le_bytes()); // LockSemaphore
        dump_buf[off + 32..off + 40].copy_from_slice(&0u64.to_le_bytes()); // SpinCount
        reinit += 1;
    }
    if reinit > 0 {
        info!(
            reinit,
            count = cs_rvas.len(),
            "Re-initialized RTL_CRITICAL_SECTION objects to unlocked state"
        );
    }
    reinit
}

pub(crate) fn reinitialize_zero_filled_data(
    pe: &PeHeader,
    dump_buf: &mut [u8],
    executable_path: Option<&Path>,
    session_modules: &[SessionModuleRange],
) -> usize {
    if !pe.is_64bit {
        return 0;
    }

    let image_base = pe.nt_headers.optional_header.image_base;
    let image_size = pe.size_of_image();

    // Always scrub raw process-local absolute pointers from writable image
    // data. Encoded cookie triples are not raw heap addresses and survive.
    let cleared_ptrs = clear_process_local_absolute_pointers(
        pe,
        dump_buf,
        image_base,
        image_size,
        session_modules,
    );
    if cleared_ptrs > 0 {
        info!(
            cleared = cleared_ptrs,
            "Cleared process-local absolute pointers from writable sections"
        );
    }

    let Some(path) = executable_path else {
        return cleared_ptrs;
    };
    let Ok(original_pe) = PeHeader::from_file(path) else {
        warn!(path = %path.display(), "Cannot inspect original PE for .data reinitialization");
        return cleared_ptrs;
    };
    let Some(original_data) = original_pe.sections.iter().find(|s| s.name == ".data") else {
        return cleared_ptrs;
    };
    if original_data.header.size_of_raw_data != 0 {
        return cleared_ptrs;
    }

    let Some(data) = pe
        .sections
        .iter()
        .find(|s| s.name == ".data" && s.virtual_address == original_data.virtual_address)
    else {
        return cleared_ptrs;
    };

    let start = data.virtual_address as usize;
    let end = start
        .saturating_add(data.virtual_size as usize)
        .min(dump_buf.len());
    if end.saturating_sub(start) < POINTER_TRIPLE_SIZE {
        return cleared_ptrs;
    }

    let Some(cookie) = find_security_cookie(&dump_buf[start..end]) else {
        warn!(
            data_rva = format_args!("{:#x}", data.virtual_address),
            "SecurityCookie not found in .data"
        );
        return cleared_ptrs;
    };

    let offsets =
        reset_stale_encoded_containers(&mut dump_buf[start..end], cookie, image_base, image_size);
    let rvas: Vec<String> = offsets
        .iter()
        .map(|offset| format!("{:#x}", data.virtual_address as usize + offset))
        .collect();
    info!(
        cookie = format_args!("{cookie:#x}"),
        containers = offsets.len(),
        rvas = %rvas.join(", "),
        "Reset stale SecurityCookie-encoded .data containers"
    );
    cleared_ptrs.saturating_add(offsets.len())
}

/// Zero 8-byte absolute pointers that point into process-local user address
/// space outside the image. Image-relative pointers and non-pointer scalars
/// are preserved so CRT can reinitialize heap/stdio from a clean BSS-like
/// baseline on the next process start.
///
/// `session_modules` carries the module ranges of the *dumped* session (the
/// dumped image itself excluded). A high-ASLR pointer landing inside one of
/// those ranges is a stale session pointer — the system DLL it referenced is
/// re-based by ASLR on the next boot — and is zeroed so load-time resolution
/// rebinds it. An empty table keeps the historical behaviour (never clear the
/// high-ASLR band).
fn clear_process_local_absolute_pointers(
    pe: &PeHeader,
    dump_buf: &mut [u8],
    image_base: u64,
    image_size: u32,
    session_modules: &[SessionModuleRange],
) -> usize {
    let image_end = image_base.saturating_add(image_size as u64);
    let mut cleared = 0usize;

    // Restrict to classic MSVC `.data` / blank-name RW data (pure rebuild may
    // space-pad names). Exclude executable and RWX (`.wfix` / `.fill` code).
    //
    // Themida keeps decrypted code in zero-raw `.fill` gaps (W, non-X) until
    // materialize promotes them to `.wfix`. Scrubbing those pages treats
    // instruction bytes as heap pointers — e.g. `btr …; movabs rsi,0` encodes
    // `A0 48 BE 00 00 00 00 00` = 0xBE48A0 and becomes eleven `00`s, then AV on
    // `add [rax],al`. `.wfix` (RWX) is excluded the same way.
    for section in pe.sections.iter().filter(|s| {
        s.characteristics & IMAGE_SCN_MEM_WRITE != 0
            && s.characteristics & IMAGE_SCN_MEM_EXECUTE == 0
            && is_data_like_section_name(&s.name)
    }) {
        let start = section.virtual_address as usize;
        let end = start
            .saturating_add(section.virtual_size as usize)
            .min(dump_buf.len());
        if end.saturating_sub(start) < 8 {
            continue;
        }

        let aligned_start = (start + 7) & !7;
        for offset in (aligned_start..end.saturating_sub(7)).step_by(8) {
            let value =
                u64::from_le_bytes(dump_buf[offset..offset + 8].try_into().unwrap_or_default());
            if is_stale_absolute_pointer(value, image_base, image_end, session_modules) {
                dump_buf[offset..offset + 8].fill(0);
                cleared += 1;
            }
        }
    }

    cleared
}

/// True when a QWORD in dumped `.data` is a process-local absolute pointer that
/// must not survive into an independent PE image.
///
/// Three classes (Origin W1 / R-LOAD-FLAKE / T0.7 session binding):
/// 1. **Low 4GB heap-like** — aligned, `MIN_USER_POINTER..=MAX_PROCESS_LOCAL_HEAP_POINTER`,
///    outside the image (classic CRT/heap tables).
/// 2. **Kernel-canonical garbage** — `>= KERNEL_CANONICAL_MIN` and not `!0`
///    (sentinel). Observed as object-head slots (e.g. RVA `0xfc388`) that AV at
///    `xchg [r10]`. Alignment is **not** required: the Origin crash pointer
///    ends in `…dcd`.
/// 3. **Stale session module pointer** — `>= HIGH_ASLR_MODULE_MIN` and landing
///    inside a module range of the *dumped* session (system DLL base captured
///    at dump time). ASLR re-bases those modules on every boot, so a
///    `keep_runtime_base` product embedding the old session's absolute address
///    (e.g. RVA `0x112c10` = old ntdll `0x7ffeeb426390`) AVs on the next
///    session. Zeroed so load-time resolution rebinds. Image-own high-ASLR VAs
///    are **not** in the table (the module snapshot skips the dumped image)
///    and survive until `fix_hardcoded_addresses` rebases them.
fn is_stale_absolute_pointer(
    value: u64,
    image_base: u64,
    image_end: u64,
    session_modules: &[SessionModuleRange],
) -> bool {
    if (image_base..image_end).contains(&value) {
        return false;
    }
    if is_kernel_canonical_garbage(value) {
        return true;
    }
    if !(MIN_USER_POINTER..=MAX_PROCESS_LOCAL_HEAP_POINTER).contains(&value) {
        return false;
    }
    // High ASLR module band. Image-own VAs must survive until rebase (Origin
    // W1), but a value inside a captured session module is a stale session
    // pointer (T0.7). With an empty session table (no module capture), keep
    // the historical behaviour — never clear this band.
    if value >= HIGH_ASLR_MODULE_MIN {
        return matches_session_module(session_modules, value);
    }
    // Low 4GB: prefer 8-byte aligned heap-like pointers; unaligned values are
    // more often packed constants / cookie fragments than CRT table entries.
    if value <= MAX_LOW_HEAP_POINTER {
        return value & 7 == 0;
    }
    // Mid-user (above 4GB, below high-module band): clear all non-image
    // addresses, including unaligned Themida heap slots (e.g. 0x2b992ddfa232).
    true
}

/// True when `value` falls inside any module range of the dumped session.
/// The snapshot excludes the dumped image itself, so a hit is a stale
/// cross-module pointer (system DLL / dependency) of the old ASLR session.
fn matches_session_module(session_modules: &[SessionModuleRange], value: u64) -> bool {
    session_modules
        .iter()
        .any(|(_, base, end)| *base <= value && value < *end)
}

fn is_kernel_canonical_garbage(value: u64) -> bool {
    // Keep all-ones sentinel triples used next to some Origin globals.
    value >= KERNEL_CANONICAL_MIN && value != u64::MAX
}

pub(crate) fn is_data_like_section_name(name: &str) -> bool {
    if name == ".data" || name.starts_with(".data") {
        return true;
    }
    // Pure-rebuild / some dumps pad names with spaces → empty after trim.
    let t = name.trim();
    t.is_empty() || t == ".data" || t.starts_with(".data")
}

#[cfg(test)]
#[allow(dead_code)]
fn is_process_local_absolute_pointer(
    value: u64,
    image_base: u64,
    image_end: u64,
    session_modules: &[SessionModuleRange],
) -> bool {
    is_stale_absolute_pointer(value, image_base, image_end, session_modules)
}

fn find_security_cookie(data: &[u8]) -> Option<u64> {
    data.windows(16).step_by(8).find_map(|pair| {
        let first = u64::from_le_bytes(pair[0..8].try_into().ok()?);
        let second = u64::from_le_bytes(pair[8..16].try_into().ok()?);
        if is_plausible_cookie(first) && second == !first {
            Some(first)
        } else if is_plausible_cookie(second) && first == !second {
            Some(second)
        } else {
            None
        }
    })
}

pub(crate) fn find_security_cookie_in_data(data: &[u8]) -> Option<u64> {
    find_security_cookie(data)
}

pub(crate) fn decode_pointer(encoded: u64, cookie: u64) -> u64 {
    (encoded ^ cookie).rotate_right((cookie & 63) as u32)
}

pub(crate) fn encode_pointer(pointer: u64, cookie: u64) -> u64 {
    pointer.rotate_left((cookie & 63) as u32) ^ cookie
}

fn is_plausible_cookie(value: u64) -> bool {
    value != 0 && value != u64::MAX && value <= 0x0000_ffff_ffff_ffff
}

fn reset_stale_encoded_containers(
    data: &mut [u8],
    cookie: u64,
    image_base: u64,
    image_size: u32,
) -> Vec<usize> {
    let image_end = image_base.saturating_add(image_size as u64);
    let mut offsets = Vec::new();

    for offset in (0..=data.len().saturating_sub(POINTER_TRIPLE_SIZE)).step_by(8) {
        let begin = decode_pointer(read_u64(data, offset), cookie);
        let end = decode_pointer(read_u64(data, offset + 8), cookie);
        let capacity = decode_pointer(read_u64(data, offset + 16), cookie);

        let ordered_heap_range = (MIN_USER_POINTER..=MAX_USER_POINTER).contains(&begin)
            && begin <= end
            && end <= capacity
            && capacity.saturating_sub(begin) <= MAX_CONTAINER_SPAN;
        let outside_image = !(image_base..image_end).contains(&begin)
            && !(image_base..image_end).contains(&end)
            && !(image_base..image_end).contains(&capacity);

        if ordered_heap_range && outside_image {
            for field in [offset, offset + 8, offset + 16] {
                data[field..field + 8].copy_from_slice(&cookie.to_le_bytes());
            }
            offsets.push(offset);
        }
    }

    offsets
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_pointer(pointer: u64, cookie: u64) -> u64 {
        super::encode_pointer(pointer, cookie)
    }

    #[test]
    fn finds_cookie_followed_by_complement() {
        let cookie: u64 = 0x3497_64dd_2eee;
        let mut data = vec![0u8; 32];
        data[8..16].copy_from_slice(&cookie.to_le_bytes());
        data[16..24].copy_from_slice(&(!cookie).to_le_bytes());
        assert_eq!(find_security_cookie(&data), Some(cookie));

        data[8..16].copy_from_slice(&(!cookie).to_le_bytes());
        data[16..24].copy_from_slice(&cookie.to_le_bytes());
        assert_eq!(find_security_cookie(&data), Some(cookie));
    }

    #[test]
    fn resets_only_ordered_heap_pointer_triples() {
        let cookie = 0x3497_64dd_2eee;
        let mut data = vec![0x55; 80];
        for (index, pointer) in [0x963530, 0x963578, 0x963630].into_iter().enumerate() {
            let encoded = encode_pointer(pointer, cookie);
            data[16 + index * 8..24 + index * 8].copy_from_slice(&encoded.to_le_bytes());
        }

        let offsets = reset_stale_encoded_containers(&mut data, cookie, 0x140000000, 0x200000);

        assert_eq!(offsets, vec![16]);
        assert!(data[16..40]
            .chunks_exact(8)
            .all(|field| u64::from_le_bytes(field.try_into().unwrap()) == cookie));
        assert!(data[..16].iter().all(|&byte| byte == 0x55));
        assert!(data[40..].iter().all(|&byte| byte == 0x55));
    }

    #[test]
    fn preserves_encoded_image_and_unordered_values() {
        let cookie = 0x3497_64dd_2eee;
        let mut data = vec![0u8; 48];
        for (index, pointer) in [0x140001000, 0x140001008, 0x140001010]
            .into_iter()
            .enumerate()
        {
            let encoded = encode_pointer(pointer, cookie);
            data[index * 8..index * 8 + 8].copy_from_slice(&encoded.to_le_bytes());
        }
        for (index, pointer) in [0x900000, 0x800000, 0x910000].into_iter().enumerate() {
            let encoded = encode_pointer(pointer, cookie);
            data[24 + index * 8..32 + index * 8].copy_from_slice(&encoded.to_le_bytes());
        }
        let original = data.clone();

        assert!(
            reset_stale_encoded_containers(&mut data, cookie, 0x140000000, 0x200000).is_empty()
        );
        assert_eq!(data, original);
    }

    #[test]
    fn clears_origin_kernel_garbage_object_head() {
        // Live Origin pure dump: RVA 0xfc388 held 0xffffd466d2205dcd → AV at
        // o+0x39e5c (xchg [r10]). Must clear even when unaligned.
        let image_base = 0x140000000u64;
        let image_end = image_base + 0x19f000;
        // T0.7: an empty session table must preserve the historical behaviour
        // (never clear the high-ASLR band) — the regression baseline.
        let no_modules: &[SessionModuleRange] = &[];
        let bad = 0xffff_d466_d220_5dcd;
        assert!(is_stale_absolute_pointer(
            bad, image_base, image_end, no_modules
        ));
        assert!(is_kernel_canonical_garbage(bad));
        // Sentinel next door stays.
        assert!(!is_stale_absolute_pointer(
            u64::MAX,
            image_base,
            image_end,
            no_modules
        ));
        // Image VA stays (observed neighbor at 0xfc388+0x28).
        assert!(!is_stale_absolute_pointer(
            0x1401_0a690,
            image_base,
            image_end,
            no_modules
        ));
        // Low user heap (aligned) still cleared.
        assert!(is_stale_absolute_pointer(
            0x8d3e40, image_base, image_end, no_modules
        ));
        // High ASLR image VA must NOT be cleared (CRT fn table before rebase),
        // even though it sits in the high-ASLR band — it is not in the table.
        assert!(!is_stale_absolute_pointer(
            0x0000_7ff7_2537_1200,
            image_base,
            image_end,
            no_modules
        ));
        // Unaligned low-user constant left alone.
        assert!(!is_stale_absolute_pointer(
            0x8d3e41, image_base, image_end, no_modules
        ));
        // Mid-user unaligned Themida heap slot is cleared (6211e6c intent).
        assert!(is_stale_absolute_pointer(
            0x0000_2b99_2ddf_a232,
            image_base,
            image_end,
            no_modules
        ));
    }

    #[test]
    fn clears_stale_session_system_dll_pointers() {
        // T0.7: keep_runtime_base product embedded the old session's ntdll
        // base (0x7ffeeb426390); after ASLR re-bases ntdll on the next boot
        // the fixed pointer AVs at startup (T0.5: RVA 0x112c10). The session
        // module table captured at dump time must identify it as stale.
        let image_base = 0x140000000u64;
        let image_end = image_base + 0x19f000;
        let session: &[SessionModuleRange] = &[
            ("ntdll.dll".to_string(), 0x7ffeeb320000, 0x7ffeeb620000),
            ("kernel32.dll".to_string(), 0x7ffa952a0000, 0x7ffa95370000),
            ("urlmon.dll".to_string(), 0x7ff9f1000000, 0x7ff9f1400000),
        ];
        // Old-session ntdll base from the T0.5 evidence: inside ntdll range.
        assert!(is_stale_absolute_pointer(
            0x7ffeeb426390,
            image_base,
            image_end,
            session
        ));
        // A kernel32 export address inside the captured range: stale too.
        assert!(is_stale_absolute_pointer(
            0x7ffa952a1000,
            image_base,
            image_end,
            session
        ));
        // Range end is exclusive: one-past-end is NOT owned by the module.
        assert!(!is_stale_absolute_pointer(
            0x7ffeeb620000,
            image_base,
            image_end,
            session
        ));
        // Base start is inclusive.
        assert!(is_stale_absolute_pointer(
            0x7ffeeb320000,
            image_base,
            image_end,
            session
        ));
        // Module-name payload is ignored by the range check (shape-only).
        assert!(matches_session_module(session, 0x7ff9f1234000));
    }

    #[test]
    fn session_table_missing_or_non_matching_preserves_high_aslr() {
        // T0.7: no session table (dump without module capture) or a value in
        // the high-ASLR band not owned by any captured module must keep the
        // historical behaviour — the pointer survives for rebase (Origin W1).
        let image_base = 0x140000000u64;
        let image_end = image_base + 0x19f000;
        let empty: &[SessionModuleRange] = &[];
        let other_session: &[SessionModuleRange] =
            &[("user32.dll".to_string(), 0x7ff8_1234_0000, 0x7ff8_1235_0000)];
        let old_ntdll = 0x7ffeeb426390u64;
        let image_own_va = 0x0000_7ff7_2537_1200u64;

        // No table → never clear the band (regression guard).
        assert!(!is_stale_absolute_pointer(
            old_ntdll, image_base, image_end, empty
        ));
        // Table present but the value is an image-own VA (not captured) → keep.
        assert!(!is_stale_absolute_pointer(
            image_own_va,
            image_base,
            image_end,
            other_session
        ));
        // Table present but the old ntdll is not in *this* table → keep.
        assert!(!is_stale_absolute_pointer(
            old_ntdll,
            image_base,
            image_end,
            other_session
        ));
        // Low user heap still cleared regardless of the session table.
        assert!(is_stale_absolute_pointer(
            0x8d3e40,
            image_base,
            image_end,
            other_session
        ));
    }
}
