//! Reset stale process-local containers captured in a dumped `.data` section.

use std::path::Path;

use tracing::{info, warn};

use crate::header::PeHeader;

const POINTER_TRIPLE_SIZE: usize = 24;
const MIN_USER_POINTER: u64 = 0x1_0000;
const MAX_USER_POINTER: u64 = 0x0000_7fff_ffff_ffff;
/// Absolute CRT/heap pointers observed in dumped Themida images land in the
/// low 4GB of the process (e.g. `0x8d3e40`, `0x8a0000`). SecurityCookie and
/// other high-entropy constants sit well above that range and must stay.
const MAX_PROCESS_LOCAL_HEAP_POINTER: u64 = 0x0000_0000_ffff_ffff;
const MAX_CONTAINER_SPAN: u64 = 0x1000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Reset SecurityCookie-encoded `{begin, end, capacity}` triples whose decoded
/// pointers refer to process-local heap memory, and clear raw process-local
/// absolute pointers (CRT heap handles, `_pioinfo`, stdio tables, etc.).
///
/// Keeping those live-process addresses in an independent dump makes the CRT
/// re-entry path (e.g. `__scrt_common_main_seh`) dereference freed heap and
/// AV at `_pioinfo[i]->_ptr` / similar globals.
pub(crate) fn reinitialize_zero_filled_data(
    pe: &PeHeader,
    dump_buf: &mut [u8],
    executable_path: Option<&Path>,
) -> usize {
    if !pe.is_64bit {
        return 0;
    }

    let image_base = pe.nt_headers.optional_header.image_base;
    let image_size = pe.size_of_image();

    // Always scrub raw process-local absolute pointers from writable image
    // data. Encoded cookie triples are not raw heap addresses and survive.
    let cleared_ptrs = clear_process_local_absolute_pointers(pe, dump_buf, image_base, image_size);
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
fn clear_process_local_absolute_pointers(
    pe: &PeHeader,
    dump_buf: &mut [u8],
    image_base: u64,
    image_size: u32,
) -> usize {
    let image_end = image_base.saturating_add(image_size as u64);
    let mut cleared = 0usize;

    // Restrict to classic MSVC `.data` only.
    //
    // Themida keeps decrypted code in zero-raw `.fill` gaps (W, non-X) until
    // materialize promotes them to `.wfix`. Scrubbing those pages treats
    // instruction bytes as heap pointers — e.g. `btr …; movabs rsi,0` encodes
    // `A0 48 BE 00 00 00 00 00` = 0xBE48A0 and becomes eleven `00`s, then AV on
    // `add [rax],al`. `.wfix` (RWX) is excluded the same way.
    for section in pe.sections.iter().filter(|s| {
        s.characteristics & IMAGE_SCN_MEM_WRITE != 0
            && s.characteristics & IMAGE_SCN_MEM_EXECUTE == 0
            && (s.name == ".data" || s.name.starts_with(".data"))
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
            if is_process_local_absolute_pointer(value, image_base, image_end) {
                dump_buf[offset..offset + 8].fill(0);
                cleared += 1;
            }
        }
    }

    cleared
}

fn is_process_local_absolute_pointer(value: u64, image_base: u64, image_end: u64) -> bool {
    if value < MIN_USER_POINTER || value > MAX_PROCESS_LOCAL_HEAP_POINTER {
        return false;
    }
    // Prefer 8-byte aligned heap-like pointers; unaligned values are more often
    // packed constants / cookie fragments than CRT table entries.
    if value & 7 != 0 {
        return false;
    }
    !(image_base..image_end).contains(&value)
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
}
