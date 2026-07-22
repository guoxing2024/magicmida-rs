//! Snapshot and restore SecurityCookie-encoded containers from live process heap.
//!
//! When a protected sample stores application-critical objects in SecurityCookie-encoded
//! containers within zero-raw sections, simply zeroing them during reconstruction prevents
//! crashes but leaves the application uninitialized. This module captures the semantic
//! contents of such containers from the live unpacking process and reconstructs them in
//! the output by:
//!
//! 1. Detecting encoded begin/end/capacity triples in `.data` that point to live heap.
//! 2. Reading the referenced heap memory from the debugger process.
//! 3. Re-allocating equivalent heap in the output process via the pre-OEP bootstrap.
//! 4. Updating the container's encoded pointers to reference the new heap.

use tracing::{debug, info, warn};

use crate::header::PeHeader;

use super::data_reinit::{decode_pointer, encode_pointer, find_security_cookie_in_data};

use super::helpers::{alloc_capped, MAX_HEAP_CONTAINER_BYTES};

const POINTER_TRIPLE_SIZE: usize = 24;
const MIN_USER_POINTER: u64 = 0x1_0000;
const MAX_USER_POINTER: u64 = 0x0000_7fff_ffff_ffff;
/// Maximum capacity−begin span accepted as a heap container candidate.
const MAX_CONTAINER_SPAN: u64 = MAX_HEAP_CONTAINER_BYTES as u64;

/// Metadata for a heap-referenced encoded container detected in `.data`.
#[derive(Debug, Clone)]
pub struct ContainerSnapshot {
    /// RVA in `.data` where the encoded triple is stored.
    pub rva: u32,
    /// Decoded begin pointer from the live unpacking process.
    pub decoded_begin: u64,
    /// Decoded end pointer.
    pub decoded_end: u64,
    /// Decoded capacity pointer (kept for debugging/validation but not used in restoration).
    #[allow(dead_code)]
    pub decoded_capacity: u64,
    /// SecurityCookie used to encode/decode.
    pub cookie: u64,
    /// Heap memory contents from [decoded_begin..decoded_end).
    pub heap_content: Vec<u8>,
}

/// Snapshot of a non-container global variable that needs runtime initialization.
///
/// These are regular variables (not SecurityCookie-encoded containers) that are
/// decrypted/initialized by the unpacker at runtime. Examples include CRT globals,
/// static initializers, or application state that Themida encrypts in the packed file.
#[derive(Debug, Clone)]
pub struct GlobalVarSnapshot {
    /// RVA in `.data` where the variable is stored.
    pub rva: u32,
    /// Size of the variable in bytes.
    pub size: usize,
    /// Runtime value from live process.
    pub value: Vec<u8>,
}

/// Detect SecurityCookie-encoded containers in zero-raw `.data` sections that
/// point to live heap memory outside the image. Reads the heap content from
/// the live process via debugger API.
pub fn detect_containers(
    pe: &PeHeader,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
) -> Vec<ContainerSnapshot> {
    if !pe.is_64bit {
        return Vec::new();
    }

    let data = match pe.sections.iter().find(|s| s.name == ".data") {
        Some(section) => section,
        None => return Vec::new(),
    };

    let start = data.virtual_address as usize;
    let end = start
        .saturating_add(data.virtual_size as usize)
        .min(dump_buf.len());
    if end.saturating_sub(start) < POINTER_TRIPLE_SIZE {
        return Vec::new();
    }

    let Some(cookie) = find_security_cookie_in_data(&dump_buf[start..end]) else {
        return Vec::new();
    };

    let mut containers = Vec::new();
    let image_base = pe.nt_headers.optional_header.image_base;
    let image_end = image_base.saturating_add(pe.size_of_image() as u64);

    for offset in (0..=end - start - POINTER_TRIPLE_SIZE).step_by(8) {
        let triple = &dump_buf[start + offset..start + offset + POINTER_TRIPLE_SIZE];
        let encoded: [u64; 3] = [
            u64::from_le_bytes(triple[0..8].try_into().unwrap()),
            u64::from_le_bytes(triple[8..16].try_into().unwrap()),
            u64::from_le_bytes(triple[16..24].try_into().unwrap()),
        ];

        let decoded: [u64; 3] = [
            decode_pointer(encoded[0], cookie),
            decode_pointer(encoded[1], cookie),
            decode_pointer(encoded[2], cookie),
        ];

        if !is_heap_container(&decoded, image_base, image_end) {
            continue;
        }

        let rva = (start + offset) as u32;
        let size = (decoded[1] - decoded[0]) as usize;

        // Cap heap copy size — decoded pointers come from untrusted live data.
        let mut heap_content = match alloc_capped(size, MAX_HEAP_CONTAINER_BYTES, "heap container")
        {
            Ok(buf) => buf,
            Err(e) => {
                warn!(
                    rva = format_args!("{rva:#x}"),
                    heap_addr = format_args!("{:#x}", decoded[0]),
                    size,
                    error = %e,
                    "Skipping container: heap size rejected"
                );
                continue;
            }
        };
        let read_result = debugger.read_memory(decoded[0] as usize, &mut heap_content);

        if read_result.is_err() {
            warn!(
                rva = format_args!("{rva:#x}"),
                heap_addr = format_args!("{:#x}", decoded[0]),
                size,
                "Failed to read heap content for container"
            );
            continue;
        }

        debug!(
            rva = format_args!("{rva:#x}"),
            begin = format_args!("{:#x}", decoded[0]),
            end = format_args!("{:#x}", decoded[1]),
            capacity = format_args!("{:#x}", decoded[2]),
            heap_size = heap_content.len(),
            "Detected heap-referenced container"
        );

        containers.push(ContainerSnapshot {
            rva,
            decoded_begin: decoded[0],
            decoded_end: decoded[1],
            decoded_capacity: decoded[2],
            cookie,
            heap_content,
        });
    }

    if !containers.is_empty() {
        info!(
            count = containers.len(),
            "Detected heap-referenced containers requiring snapshot"
        );
    }

    containers
}

fn is_heap_container(decoded: &[u64; 3], image_base: u64, image_end: u64) -> bool {
    let [begin, end, capacity] = *decoded;

    if !(MIN_USER_POINTER..=MAX_USER_POINTER).contains(&begin) {
        return false;
    }
    if !(MIN_USER_POINTER..=MAX_USER_POINTER).contains(&end) {
        return false;
    }
    if !(MIN_USER_POINTER..=MAX_USER_POINTER).contains(&capacity) {
        return false;
    }

    if (image_base..image_end).contains(&begin) {
        return false;
    }
    // Empty [begin,end) triples are extremely common false positives and
    // rewriting them corrupts real .data values during TLS bootstrap.
    if begin >= end || end > capacity {
        return false;
    }

    let span = capacity.saturating_sub(begin);
    if span == 0 || span > MAX_CONTAINER_SPAN {
        return false;
    }

    // Real CRT/STL heap buffers are at least one pointer wide in practice.
    let used = end - begin;
    if used < 8 || used > MAX_HEAP_CONTAINER_BYTES as u64 {
        return false;
    }

    true
}

/// Restore encoded containers in the output by updating their encoded pointers
/// to reference new heap allocations. The actual heap allocation and content
/// copying will be performed by the pre-OEP bootstrap stub.
///
/// This function updates the `.data` section with new encoded pointers that
/// reference a placeholder heap base. The bootstrap will allocate actual heap
/// memory and adjust these pointers at runtime.
///
/// Returns the number of containers restored.
///
/// NOTE: This function is currently unused as container restoration is handled
/// entirely by the runtime bootstrap stub. It remains here for potential future
/// use or testing scenarios.
#[allow(dead_code)]
pub fn restore_containers(
    dump_buf: &mut [u8],
    containers: &[ContainerSnapshot],
    new_heap_base: u64,
) -> usize {
    let mut restored = 0;

    for container in containers {
        let rva = container.rva as usize;
        if rva + POINTER_TRIPLE_SIZE > dump_buf.len() {
            warn!(
                rva = format_args!("{:#x}", container.rva),
                "Container RVA beyond dump buffer"
            );
            continue;
        }

        let size = container
            .decoded_end
            .saturating_sub(container.decoded_begin);
        let capacity_size = container
            .decoded_capacity
            .saturating_sub(container.decoded_begin);
        let new_begin = new_heap_base;
        let new_end = new_begin.saturating_add(size);
        let new_capacity = new_begin.saturating_add(capacity_size);

        let encoded = [
            encode_pointer(new_begin, container.cookie),
            encode_pointer(new_end, container.cookie),
            encode_pointer(new_capacity, container.cookie),
        ];

        dump_buf[rva..rva + 8].copy_from_slice(&encoded[0].to_le_bytes());
        dump_buf[rva + 8..rva + 16].copy_from_slice(&encoded[1].to_le_bytes());
        dump_buf[rva + 16..rva + 24].copy_from_slice(&encoded[2].to_le_bytes());

        debug!(
            rva = format_args!("{:#x}", container.rva),
            new_begin = format_args!("{new_begin:#x}"),
            size,
            "Restored container with new heap pointers"
        );

        restored += 1;
    }

    if restored > 0 {
        info!(restored, "Restored heap-referenced containers");
    }

    restored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_containers_restore_nothing() {
        let mut buf = vec![0u8; 0x1000];
        assert_eq!(restore_containers(&mut buf, &[], 0x900000), 0);
    }

    #[test]
    fn rejects_empty_begin_end_triples() {
        let image_base = 0x140000000;
        let image_end = image_base + 0x100000;
        // begin == end was previously accepted and rewrote thousands of .data slots.
        assert!(!is_heap_container(
            &[0x500000, 0x500000, 0x500100],
            image_base,
            image_end
        ));
        assert!(is_heap_container(
            &[0x500000, 0x500100, 0x500200],
            image_base,
            image_end
        ));
    }

    #[test]
    fn restores_single_container() {
        let cookie = 0x3497_64dd_2eee;
        let mut buf = vec![0u8; 0x1000];

        let snapshot = ContainerSnapshot {
            rva: 0x100,
            decoded_begin: 0x500000,
            decoded_end: 0x500100,
            decoded_capacity: 0x500200,
            cookie,
            heap_content: vec![0xaa; 0x100],
        };

        let new_heap = 0x700000;
        assert_eq!(restore_containers(&mut buf, &[snapshot], new_heap), 1);

        let restored: [u64; 3] = [
            u64::from_le_bytes(buf[0x100..0x108].try_into().unwrap()),
            u64::from_le_bytes(buf[0x108..0x110].try_into().unwrap()),
            u64::from_le_bytes(buf[0x110..0x118].try_into().unwrap()),
        ];

        assert_eq!(decode_pointer(restored[0], cookie), new_heap);
        assert_eq!(decode_pointer(restored[1], cookie), new_heap + 0x100);
        assert_eq!(decode_pointer(restored[2], cookie), new_heap + 0x200);
    }
}
