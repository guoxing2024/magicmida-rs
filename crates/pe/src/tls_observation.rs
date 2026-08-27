//! Immutable runtime observation of a PE image's TLS directory.
//!
//! Production `.unwrap()`s are parse invariants: `parse_directory` runs only
//! after an `ExactReadResult::Complete` read of the TLS directory (>= 40
//! bytes, covering the deepest slice), and `read_ptr` matches the pointer
//! width before the fixed-width slice (WO-10). Test unwraps are assertions.
#![allow(clippy::unwrap_used)]
//!
//! This module is deliberately independent from dump mutation. It reads the
//! initial PE header's TLS data-directory and the live process memory before
//! any header patching, shrinking, or section reconstruction occurs.

use std::fmt;

use crate::header::PeHeader;

/// IMAGE_DIRECTORY_ENTRY_TLS.
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
/// Maximum number of callback pointer slots scanned before requiring a NULL.
pub const MAX_TLS_CALLBACK_SLOTS: usize = 4096;
/// IMAGE_SCN_MEM_EXECUTE.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Result classification for one observed TLS callback slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCallbackStatus {
    Resolved,
    ZeroTerminator,
    ShortRead,
    InvalidAddress,
    NonExecutable,
    InvalidByteCount,
    ReadError,
}

impl fmt::Display for TlsCallbackStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Resolved => "Resolved",
            Self::ZeroTerminator => "ZeroTerminator",
            Self::ShortRead => "ShortRead",
            Self::InvalidAddress => "InvalidAddress",
            Self::NonExecutable => "NonExecutable",
            Self::InvalidByteCount => "InvalidByteCount",
            Self::ReadError => "ReadError",
        })
    }
}

/// Immutable evidence for one TLS callback pointer slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCallbackObservation {
    pub slot_index: usize,
    pub slot_address: u64,
    pub bytes_read: usize,
    pub observed_value: Option<u64>,
    pub callback_rva: Option<u32>,
    pub status: TlsCallbackStatus,
}

/// Immutable runtime TLS observation captured at the dump boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsObservationReport {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_bytes_read: usize,

    pub start_address_of_raw_data: u64,
    pub start_rva: Option<u32>,
    pub end_address_of_raw_data: u64,
    pub end_rva: Option<u32>,
    pub address_of_index: u64,
    pub index_rva: Option<u32>,
    pub address_of_callbacks: u64,
    pub callbacks_rva: Option<u32>,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,

    pub index_bytes_read: usize,
    pub index_value: Option<u32>,
    pub callback_slots: Vec<TlsCallbackObservation>,
    pub null_terminated: bool,
    pub blockers: Vec<String>,
}

impl TlsObservationReport {
    /// Returns true when the observation has no fail-closed blocker.
    ///
    /// A missing TLS directory is a complete negative observation, not a
    /// failure. The later acceptance gate can require `directory_present` for
    /// samples that are expected to use TLS.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.blockers.is_empty()
    }

    /// Stable human-readable summary for diagnostics.
    #[must_use]
    pub fn failure_summary(&self) -> String {
        if self.blockers.is_empty() {
            if self.directory_present {
                "TLS observation complete".to_string()
            } else {
                "TLS directory absent (complete negative observation)".to_string()
            }
        } else {
            self.blockers.join("; ")
        }
    }
}

/// Observe TLS using a caller-provided memory reader.
///
/// The reader must return the number of bytes actually read. Short reads are
/// recorded as evidence and never treated as successful exact reads.
pub fn observe_tls_runtime<F, E>(
    pe: &PeHeader,
    load_base: u64,
    mut read_memory: F,
) -> TlsObservationReport
where
    F: FnMut(u64, &mut [u8]) -> Result<usize, E>,
    E: fmt::Display,
{
    let directory = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];
    let pointer_size = if pe.is_64bit { 8 } else { 4 };
    let directory_present = directory.virtual_address != 0 || directory.size != 0;
    let mut report = TlsObservationReport {
        directory_present,
        pe32_plus: pe.is_64bit,
        pointer_size,
        directory_rva: directory.virtual_address,
        directory_size: directory.size,
        directory_bytes_read: 0,
        start_address_of_raw_data: 0,
        start_rva: None,
        end_address_of_raw_data: 0,
        end_rva: None,
        address_of_index: 0,
        index_rva: None,
        address_of_callbacks: 0,
        callbacks_rva: None,
        size_of_zero_fill: 0,
        characteristics: 0,
        index_bytes_read: 0,
        index_value: None,
        callback_slots: Vec::new(),
        null_terminated: false,
        blockers: Vec::new(),
    };

    if !directory_present {
        return report;
    }

    // The PE data-directory tuple is either wholly absent or wholly present.
    // A partial tuple is malformed and must never be used to derive a memory
    // address for a synthetic TLS directory read.
    if (directory.virtual_address == 0) != (directory.size == 0) {
        report.blockers.push(format!(
            "TLS data-directory tuple is partial: RVA {:#x}, size {:#x}",
            directory.virtual_address, directory.size
        ));
        return report;
    }

    let expected_size = if pe.is_64bit { 40usize } else { 24usize };
    if usize::try_from(directory.size).is_ok_and(|size| size < expected_size) {
        report.blockers.push(format!(
            "TLS directory size {} is smaller than {} bytes for {}",
            directory.size,
            expected_size,
            if pe.is_64bit { "PE32+" } else { "PE32" }
        ));
    }

    if let Err(reason) = validate_rva_range(
        directory.virtual_address,
        expected_size,
        pe.nt_headers.optional_header.size_of_image,
    ) {
        report.blockers.push(format!(
            "TLS directory RVA range [{:#x}, ...) is invalid: {reason}",
            directory.virtual_address
        ));
        return report;
    }

    let Some(directory_address) = load_base.checked_add(u64::from(directory.virtual_address))
    else {
        report
            .blockers
            .push("TLS directory VA overflow".to_string());
        return report;
    };
    let mut directory_bytes = vec![0u8; expected_size];
    if !matches!(
        read_exact_into(
            &mut read_memory,
            directory_address,
            &mut directory_bytes,
            &mut report.directory_bytes_read,
            &mut report.blockers,
            "TLS directory",
        ),
        ExactReadResult::Complete
    ) {
        return report;
    }

    parse_directory(&mut report, &directory_bytes);

    report.start_rva = address_to_rva(
        report.start_address_of_raw_data,
        load_base,
        pe.nt_headers.optional_header.size_of_image,
    );
    report.end_rva = address_to_rva_end(
        report.end_address_of_raw_data,
        load_base,
        pe.nt_headers.optional_header.size_of_image,
    );
    for (label, va, rva) in [
        (
            "TLS StartAddressOfRawData",
            report.start_address_of_raw_data,
            report.start_rva,
        ),
        (
            "TLS EndAddressOfRawData",
            report.end_address_of_raw_data,
            report.end_rva,
        ),
    ] {
        if va != 0 && rva.is_none() {
            report
                .blockers
                .push(format!("{label} VA {va:#x} is outside the runtime image"));
        }
    }
    if (report.start_address_of_raw_data == 0) != (report.end_address_of_raw_data == 0) {
        report.blockers.push(
            "TLS raw-data start/end addresses must be both zero or both non-zero".to_string(),
        );
    }

    if let Some(start) = report.start_rva {
        if let Some(end) = report.end_rva {
            if start > end {
                report.blockers.push(format!(
                    "TLS raw-data range is reversed: start RVA {start:#x} > end RVA {end:#x}"
                ));
            }
        }
    }

    if report.address_of_index == 0 {
        report
            .blockers
            .push("TLS AddressOfIndex is zero".to_string());
    } else if let Some(index_rva) = address_to_rva(
        report.address_of_index,
        load_base,
        pe.nt_headers.optional_header.size_of_image,
    ) {
        report.index_rva = Some(index_rva);
        match exact_va_rva(
            report.address_of_index,
            load_base,
            pe.nt_headers.optional_header.size_of_image,
            4,
        ) {
            Ok(_) => {
                let mut index_bytes = [0u8; 4];
                if matches!(
                    read_exact_into(
                        &mut read_memory,
                        report.address_of_index,
                        &mut index_bytes,
                        &mut report.index_bytes_read,
                        &mut report.blockers,
                        "TLS index",
                    ),
                    ExactReadResult::Complete
                ) {
                    report.index_value = Some(u32::from_le_bytes(index_bytes));
                }
            }
            Err(reason) => report.blockers.push(format!(
                "TLS AddressOfIndex VA {:#x} exact 4-byte range is invalid: {reason}",
                report.address_of_index
            )),
        }
    } else {
        report.blockers.push(format!(
            "TLS AddressOfIndex VA {:#x} is outside the runtime image",
            report.address_of_index
        ));
    }

    if report.address_of_callbacks == 0 {
        // No callback array is a valid TLS configuration; there is no array
        // terminator to scan, so treat it as vacuously terminated.
        report.null_terminated = true;
        return report;
    }

    let Some(callbacks_rva) = address_to_rva(
        report.address_of_callbacks,
        load_base,
        pe.nt_headers.optional_header.size_of_image,
    ) else {
        report.blockers.push(format!(
            "TLS AddressOfCallbacks VA {:#x} is outside the runtime image",
            report.address_of_callbacks
        ));
        return report;
    };
    report.callbacks_rva = Some(callbacks_rva);

    for slot_index in 0..MAX_TLS_CALLBACK_SLOTS {
        let Some(offset) = slot_index.checked_mul(pointer_size) else {
            report
                .blockers
                .push("TLS callback slot offset overflow".to_string());
            break;
        };
        let Ok(offset_u64) = u64::try_from(offset) else {
            report
                .blockers
                .push("TLS callback slot offset does not fit in VA".to_string());
            break;
        };
        let Some(slot_address) = report.address_of_callbacks.checked_add(offset_u64) else {
            report
                .blockers
                .push("TLS callback slot VA overflow".to_string());
            break;
        };
        if let Err(reason) = exact_va_rva(
            slot_address,
            load_base,
            pe.nt_headers.optional_header.size_of_image,
            pointer_size,
        ) {
            report.blockers.push(format!(
                "TLS callback slot {slot_index} VA {slot_address:#x} exact {pointer_size}-byte range is invalid: {reason}"
            ));
            report.callback_slots.push(TlsCallbackObservation {
                slot_index,
                slot_address,
                bytes_read: 0,
                observed_value: None,
                callback_rva: None,
                status: TlsCallbackStatus::InvalidAddress,
            });
            break;
        }

        let mut slot_bytes = vec![0u8; pointer_size];
        let mut bytes_read = 0usize;
        let read_result = read_exact_into(
            &mut read_memory,
            slot_address,
            &mut slot_bytes,
            &mut bytes_read,
            &mut report.blockers,
            &format!("TLS callback slot {slot_index}"),
        );
        if read_result != ExactReadResult::Complete {
            let status = match read_result {
                ExactReadResult::ShortRead => TlsCallbackStatus::ShortRead,
                ExactReadResult::InvalidByteCount => TlsCallbackStatus::InvalidByteCount,
                ExactReadResult::ReadError => TlsCallbackStatus::ReadError,
                ExactReadResult::Complete => unreachable!("handled above"),
            };
            report.callback_slots.push(TlsCallbackObservation {
                slot_index,
                slot_address,
                bytes_read,
                observed_value: None,
                callback_rva: None,
                status,
            });
            break;
        }

        let observed_value = if pe.is_64bit {
            u64::from_le_bytes(slot_bytes[..8].try_into().expect("pointer-sized read"))
        } else {
            u32::from_le_bytes(slot_bytes[..4].try_into().expect("pointer-sized read")) as u64
        };
        if observed_value == 0 {
            report.callback_slots.push(TlsCallbackObservation {
                slot_index,
                slot_address,
                bytes_read,
                observed_value: Some(0),
                callback_rva: None,
                status: TlsCallbackStatus::ZeroTerminator,
            });
            report.null_terminated = true;
            break;
        }

        let callback_rva = address_to_rva(
            observed_value,
            load_base,
            pe.nt_headers.optional_header.size_of_image,
        );
        let status = match callback_rva {
            None => {
                report.blockers.push(format!(
                    "TLS callback slot {slot_index} VA {observed_value:#x} is outside the runtime image"
                ));
                TlsCallbackStatus::InvalidAddress
            }
            Some(rva) if !is_executable_rva(pe, rva) => {
                report.blockers.push(format!(
                    "TLS callback slot {slot_index} RVA {rva:#x} is not in an executable section"
                ));
                TlsCallbackStatus::NonExecutable
            }
            Some(_) => TlsCallbackStatus::Resolved,
        };
        report.callback_slots.push(TlsCallbackObservation {
            slot_index,
            slot_address,
            bytes_read,
            observed_value: Some(observed_value),
            callback_rva,
            status,
        });
    }

    if !report.null_terminated && report.callback_slots.len() == MAX_TLS_CALLBACK_SLOTS {
        report.blockers.push(format!(
            "TLS callback array has no NULL terminator within {} slots",
            MAX_TLS_CALLBACK_SLOTS
        ));
    }

    report
}

fn parse_directory(report: &mut TlsObservationReport, bytes: &[u8]) {
    let ptr = report.pointer_size;
    report.start_address_of_raw_data = read_ptr(bytes, 0, ptr);
    report.end_address_of_raw_data = read_ptr(bytes, ptr, ptr);
    report.address_of_index = read_ptr(bytes, ptr * 2, ptr);
    report.address_of_callbacks = read_ptr(bytes, ptr * 3, ptr);
    let scalar = ptr * 4;
    report.size_of_zero_fill = u32::from_le_bytes(bytes[scalar..scalar + 4].try_into().unwrap());
    report.characteristics = u32::from_le_bytes(bytes[scalar + 4..scalar + 8].try_into().unwrap());
}

fn address_to_rva(va: u64, load_base: u64, size_of_image: u32) -> Option<u32> {
    let delta = va.checked_sub(load_base)?;
    let rva = u32::try_from(delta).ok()?;
    (rva < size_of_image).then_some(rva)
}

fn address_to_rva_end(va: u64, load_base: u64, size_of_image: u32) -> Option<u32> {
    let delta = va.checked_sub(load_base)?;
    let rva = u32::try_from(delta).ok()?;
    (rva <= size_of_image).then_some(rva)
}

fn is_executable_rva(pe: &PeHeader, rva: u32) -> bool {
    pe.sections.iter().any(|section| {
        let span = section.virtual_size.max(section.raw_size);
        let Some(end) = section.virtual_address.checked_add(span) else {
            return false;
        };
        rva >= section.virtual_address
            && rva < end
            && section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    })
}

fn read_ptr(bytes: &[u8], offset: usize, pointer_size: usize) -> u64 {
    if pointer_size == 8 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactReadResult {
    Complete,
    ShortRead,
    InvalidByteCount,
    ReadError,
}

fn read_exact_into<F, E>(
    reader: &mut F,
    address: u64,
    buf: &mut [u8],
    bytes_read: &mut usize,
    blockers: &mut Vec<String>,
    label: &str,
) -> ExactReadResult
where
    F: FnMut(u64, &mut [u8]) -> Result<usize, E>,
    E: fmt::Display,
{
    match reader(address, buf) {
        Ok(read) => {
            *bytes_read = read;
            if read > buf.len() {
                blockers.push(format!(
                    "{label} invalid byte count: reader reported {read} bytes for {}-byte buffer at {address:#x}",
                    buf.len()
                ));
                ExactReadResult::InvalidByteCount
            } else if read == buf.len() {
                ExactReadResult::Complete
            } else {
                blockers.push(format!(
                    "{label} short read: got {read} of {} bytes at {address:#x}",
                    buf.len()
                ));
                ExactReadResult::ShortRead
            }
        }
        Err(error) => {
            *bytes_read = 0;
            blockers.push(format!("{label} read failed at {address:#x}: {error}"));
            ExactReadResult::ReadError
        }
    }
}

fn validate_rva_range(rva: u32, len: usize, size_of_image: u32) -> Result<(), String> {
    let len_u32 = u32::try_from(len)
        .map_err(|_| format!("range length {len} does not fit in 32-bit RVA arithmetic"))?;
    let end = rva
        .checked_add(len_u32)
        .ok_or_else(|| format!("RVA range start {rva:#x} plus length {len:#x} overflows"))?;
    if end > size_of_image {
        return Err(format!(
            "RVA range [{rva:#x}, {end:#x}) exceeds SizeOfImage {size_of_image:#x}"
        ));
    }
    Ok(())
}

fn exact_va_rva(va: u64, load_base: u64, size_of_image: u32, len: usize) -> Result<u32, String> {
    let delta = va
        .checked_sub(load_base)
        .ok_or_else(|| format!("VA {va:#x} is below runtime image base {load_base:#x}"))?;
    let rva =
        u32::try_from(delta).map_err(|_| format!("VA {va:#x} does not convert to a 32-bit RVA"))?;
    validate_rva_range(rva, len, size_of_image)?;
    Ok(rva)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::make_minimal_pe64;
    use std::cell::Cell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemoryMap {
        bytes: HashMap<u64, Vec<u8>>,
        short_reads: HashMap<u64, usize>,
        read_calls: Cell<usize>,
    }

    impl MemoryMap {
        fn put(&mut self, address: u64, data: Vec<u8>) {
            self.bytes.insert(address, data);
        }

        fn read(&self, address: u64, out: &mut [u8]) -> Result<usize, &'static str> {
            self.read_calls.set(self.read_calls.get() + 1);
            let Some((start, data)) = self
                .bytes
                .iter()
                .find(|(start, data)| address >= **start && address - **start < data.len() as u64)
            else {
                return Err("unmapped");
            };
            let offset =
                usize::try_from(address - *start).map_err(|_| "address does not fit usize")?;
            let available = data.len() - offset;
            let requested = self.short_reads.get(&address).copied().unwrap_or(out.len());
            let count = requested.min(out.len()).min(available);
            out[..count].copy_from_slice(&data[offset..offset + count]);
            Ok(count)
        }
    }

    fn pe64(tls_rva: u32, tls_size: u32) -> PeHeader {
        let mut bytes = make_minimal_pe64();
        let nt = 0x40usize;
        let oh = nt + 24;
        let dd = oh + 112 + IMAGE_DIRECTORY_ENTRY_TLS * 8;
        bytes[dd..dd + 4].copy_from_slice(&tls_rva.to_le_bytes());
        bytes[dd + 4..dd + 8].copy_from_slice(&tls_size.to_le_bytes());
        PeHeader::from_bytes(&bytes).expect("minimal PE64")
    }

    fn pe32(tls_rva: u32, tls_size: u32) -> PeHeader {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        let nt = 0x40usize;
        bytes[nt..nt + 4].copy_from_slice(b"PE\0\0");
        bytes[nt + 4..nt + 6].copy_from_slice(&0x14cu16.to_le_bytes());
        bytes[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes());
        bytes[nt + 20..nt + 22].copy_from_slice(&0xe0u16.to_le_bytes());
        let oh = nt + 24;
        bytes[oh..oh + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[oh + 24..oh + 28].copy_from_slice(&0x400000u32.to_le_bytes());
        bytes[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[oh + 56..oh + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[oh + 60..oh + 64].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes());
        let dd = oh + 96 + IMAGE_DIRECTORY_ENTRY_TLS * 8;
        bytes[dd..dd + 4].copy_from_slice(&tls_rva.to_le_bytes());
        bytes[dd + 4..dd + 8].copy_from_slice(&tls_size.to_le_bytes());
        let sh = oh + 0xe0;
        bytes[sh..sh + 5].copy_from_slice(b".text");
        bytes[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        PeHeader::from_bytes(&bytes).expect("minimal PE32")
    }

    fn write_ptr(data: &mut [u8], offset: usize, value: u64, pointer_size: usize) {
        if pointer_size == 8 {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        } else {
            data[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
    }

    fn tls_directory(
        base: u64,
        image_rva: u32,
        pe32_plus: bool,
        callback_va: u64,
    ) -> (u64, Vec<u8>) {
        let ptr = if pe32_plus { 8 } else { 4 };
        let dir = base + image_rva as u64;
        let index = base + 0x1200;
        let callbacks = if callback_va == 0 { 0 } else { base + 0x1300 };
        let mut bytes = vec![0u8; if pe32_plus { 40 } else { 24 }];
        write_ptr(&mut bytes, 0, base + 0x1400, ptr);
        write_ptr(&mut bytes, ptr, base + 0x1408, ptr);
        write_ptr(&mut bytes, ptr * 2, index, ptr);
        write_ptr(&mut bytes, ptr * 3, callbacks, ptr);
        bytes[ptr * 4..ptr * 4 + 4].copy_from_slice(&7u32.to_le_bytes());
        bytes[ptr * 4 + 4..ptr * 4 + 8].copy_from_slice(&0xA5u32.to_le_bytes());
        (dir, bytes)
    }

    #[test]
    fn partial_tls_directory_tuple_is_blocked_without_read() {
        let base = 0x1400_0000_0;
        for (rva, size) in [(0x1100, 0), (0, 40)] {
            let pe = pe64(rva, size);
            let map = MemoryMap::default();
            let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
            assert!(report.directory_present);
            assert!(!report.is_complete());
            assert_eq!(report.directory_bytes_read, 0);
            assert_eq!(map.read_calls.get(), 0);
            assert!(report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("partial")));
        }
    }

    #[test]
    fn directory_range_at_image_tail_does_not_call_reader() {
        let base = 0x1400_0000_0;
        let probe_pe = pe64(0x1100, 40);
        let image_size = probe_pe.nt_headers.optional_header.size_of_image;
        let pe = pe64(image_size - 39, 40);
        let map = MemoryMap::default();
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert_eq!(report.directory_bytes_read, 0);
        assert_eq!(map.read_calls.get(), 0);
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("TLS directory RVA range")));
    }

    #[test]
    fn index_exact_range_at_image_tail_does_not_call_reader() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 40);
        let image_size = pe.nt_headers.optional_header.size_of_image;
        let (dir, mut tls) = tls_directory(base, 0x1100, true, 0);
        write_ptr(&mut tls, 16, base + u64::from(image_size - 1), 8);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert_eq!(report.index_bytes_read, 0);
        assert_eq!(map.read_calls.get(), 1, "directory read only");
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("AddressOfIndex") && blocker.contains("exact 4-byte")));
    }

    #[test]
    fn callback_slot_exact_range_at_image_tail_does_not_call_reader() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 40);
        let image_size = pe.nt_headers.optional_header.size_of_image;
        let (dir, mut tls) = tls_directory(base, 0x1100, true, base + 0x1600);
        write_ptr(&mut tls, 24, base + u64::from(image_size - 1), 8);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        map.put(base + 0x1200, 0u32.to_le_bytes().to_vec());
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert_eq!(report.callback_slots.len(), 1);
        assert_eq!(report.callback_slots[0].bytes_read, 0);
        assert_eq!(
            report.callback_slots[0].status,
            TlsCallbackStatus::InvalidAddress
        );
        assert_eq!(map.read_calls.get(), 2, "directory and index reads only");
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("callback slot 0")
                    && blocker.contains("exact 8-byte"))
        );
    }

    #[test]
    fn reader_over_report_is_invalid_byte_count() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 40);
        let report = observe_tls_runtime(&pe, base, |_address, buffer| {
            Ok::<usize, &'static str>(buffer.len() + 1)
        });
        assert!(!report.is_complete());
        assert_eq!(report.directory_bytes_read, 41);
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("invalid byte count")));
        assert!(!report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("short read")));
    }

    #[test]
    fn absent_tls_is_complete_negative_observation() {
        let pe = pe64(0, 0);
        let report = observe_tls_runtime(&pe, 0x1400_0000_0, |_a, _b| Ok::<_, &'static str>(0));
        assert!(!report.directory_present);
        assert!(report.is_complete());
        assert!(report.failure_summary().contains("absent"));
    }

    #[test]
    fn pe32_plus_complete_resolved_callback_and_null() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 40);
        let (dir, tls) = tls_directory(base, 0x1100, true, base + 0x1600);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        map.put(base + 0x1200, 0x1234u32.to_le_bytes().to_vec());
        let mut callbacks = vec![0u8; 16];
        write_ptr(&mut callbacks, 0, base + 0x1000, 8);
        write_ptr(&mut callbacks, 8, 0, 8);
        map.put(base + 0x1300, callbacks);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(report.is_complete(), "{}", report.failure_summary());
        assert!(report.pe32_plus);
        assert_eq!(report.pointer_size, 8);
        assert_eq!(report.index_value, Some(0x1234));
        assert_eq!(report.callback_slots.len(), 2);
        assert_eq!(report.callback_slots[0].status, TlsCallbackStatus::Resolved);
        assert_eq!(
            report.callback_slots[1].status,
            TlsCallbackStatus::ZeroTerminator
        );
        assert!(report.null_terminated);
    }

    #[test]
    fn pe32_layout_and_callbacks_zero() {
        let base = 0x400000;
        let pe = pe32(0x1100, 24);
        let (dir, tls) = tls_directory(base, 0x1100, false, 0);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        map.put(base + 0x1200, 0x55u32.to_le_bytes().to_vec());
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(report.is_complete(), "{}", report.failure_summary());
        assert_eq!(report.pointer_size, 4);
        assert_eq!(report.index_value, Some(0x55));
        assert!(report.callback_slots.is_empty());
        assert!(report.null_terminated);
    }

    #[test]
    fn directory_declared_size_short_is_blocked() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 39);
        let (dir, tls) = tls_directory(base, 0x1100, true, 0);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert!(report.blockers.iter().any(|b| b.contains("smaller than")));
    }

    #[test]
    fn directory_short_read_is_blocked() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 40);
        let (dir, tls) = tls_directory(base, 0x1100, true, 0);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        map.short_reads.insert(dir, 39);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert_eq!(report.directory_bytes_read, 39);
    }

    #[test]
    fn index_short_read_is_blocked() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 40);
        let (dir, tls) = tls_directory(base, 0x1100, true, 0);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        map.put(base + 0x1200, 0u32.to_le_bytes().to_vec());
        map.short_reads.insert(base + 0x1200, 3);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert_eq!(report.index_bytes_read, 3, "{report:?}");
    }

    #[test]
    fn callback_short_read_is_blocked() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 40);
        let (dir, tls) = tls_directory(base, 0x1100, true, base + 0x1600);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        map.put(base + 0x1200, 0u32.to_le_bytes().to_vec());
        map.put(base + 0x1300, vec![1u8; 7]);
        map.short_reads.insert(base + 0x1300, 7);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert_eq!(
            report.callback_slots[0].status,
            TlsCallbackStatus::ShortRead
        );
    }

    #[test]
    fn callback_array_cap_requires_terminator() {
        let base = 0x1400_0000_0;
        let mut pe = pe64(0x1100, 40);
        pe.nt_headers.optional_header.size_of_image =
            (0x1300usize + MAX_TLS_CALLBACK_SLOTS * 8 + 8) as u32;
        let (dir, tls) = tls_directory(base, 0x1100, true, base + 0x1600);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        map.put(base + 0x1200, 0u32.to_le_bytes().to_vec());
        map.put(base + 0x1300, vec![0u8; MAX_TLS_CALLBACK_SLOTS * 8]);
        // Fill every slot with a valid executable callback, with no NULL.
        let mut callbacks = vec![0u8; MAX_TLS_CALLBACK_SLOTS * 8];
        for i in 0..MAX_TLS_CALLBACK_SLOTS {
            write_ptr(&mut callbacks, i * 8, base + 0x1000, 8);
        }
        map.put(base + 0x1300, callbacks);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert!(!report.null_terminated);
        assert_eq!(report.callback_slots.len(), MAX_TLS_CALLBACK_SLOTS);
    }

    #[test]
    fn invalid_va_raw_range_and_non_executable_callback_are_blocked() {
        let base = 0x1400_0000_0;
        let mut pe = pe64(0x1100, 40);
        pe.sections[0].characteristics = 0x40000040;
        let (dir, mut tls) = tls_directory(base, 0x1100, true, base + 0x1600);
        write_ptr(&mut tls, 0, base + 0x1800, 8);
        write_ptr(&mut tls, 8, base + 0x1700, 8);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        map.put(base + 0x1200, 0u32.to_le_bytes().to_vec());
        let mut callbacks = vec![0u8; 16];
        write_ptr(&mut callbacks, 0, base + 0x1000, 8);
        map.put(base + 0x1300, callbacks);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert!(report
            .blockers
            .iter()
            .any(|b| b.contains("reversed") || b.contains("not in an executable")));
    }

    #[test]
    fn raw_range_out_of_image_and_low_va_are_blocked() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 40);
        let (dir, mut tls) = tls_directory(base, 0x1100, true, base + 0x1600);
        write_ptr(&mut tls, 0, base - 1, 8);
        write_ptr(&mut tls, 8, base + 0x1800, 8);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        map.put(base + 0x1200, 0u32.to_le_bytes().to_vec());
        let mut callbacks = vec![0u8; 16];
        write_ptr(&mut callbacks, 0, base - 1, 8);
        map.put(base + 0x1300, callbacks);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert!(report
            .blockers
            .iter()
            .any(|b| b.contains("StartAddressOfRawData") || b.contains("callback slot 0")));
    }

    #[test]
    fn out_of_image_index_and_callback_are_blocked() {
        let base = 0x1400_0000_0;
        let pe = pe64(0x1100, 40);
        let (dir, mut tls) = tls_directory(base, 0x1100, true, base + 0x1600);
        write_ptr(&mut tls, 16, base + 0x9000, 8);
        let mut map = MemoryMap::default();
        map.put(dir, tls);
        let report = observe_tls_runtime(&pe, base, |a, b| map.read(a, b));
        assert!(!report.is_complete());
        assert!(report.blockers.iter().any(|b| b.contains("AddressOfIndex")));
    }
}
