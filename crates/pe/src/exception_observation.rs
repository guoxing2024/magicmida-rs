//! Immutable runtime observation of a PE image's exception directory
//! (`.pdata`, data directory index 3) and its UNWIND_INFO structures.
//!
//! This module is deliberately independent from dump mutation. It reads the
//! initial PE header's exception data-directory and the live process memory
//! before any header patching, shrinking, or section reconstruction occurs
//! (GTO-H4-D D1 — same discipline as `tls_observation`).
//!
//! Every check is fail-closed: a violation records a blocker; nothing is
//! silently skipped, synthesized, or re-derived.

use std::fmt;

use crate::header::PeHeader;

/// IMAGE_DIRECTORY_ENTRY_EXCEPTION.
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
/// Size of one `IMAGE_RUNTIME_FUNCTION_ENTRY` on x64.
pub const RUNTIME_FUNCTION_SIZE: usize = 12;
/// UNWIND_INFO header size (version/flags byte, size-of-prolog, count-of-codes,
/// frame register/offset).
pub const UNWIND_INFO_HEADER_SIZE: usize = 4;
/// Maximum exception directory bytes observed (64 MiB) — E2 cap.
pub const MAX_EXCEPTION_DIRECTORY_BYTES: usize = 64 * 1024 * 1024;

/// x64 UNWIND_INFO: the optional handler/chain slot is placed on a 4-byte
/// boundary after the unwind codes (count_of_codes*2 bytes, padded to 4).
#[inline]
pub(crate) fn align_up_4(v: u32) -> u32 {
    (v + 3) & !3
}
/// IMAGE_SCN_MEM_EXECUTE.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// UNW_FLAG_* bits.
const UNW_FLAG_EHANDLER: u8 = 0x01;
const UNW_FLAG_UHANDLER: u8 = 0x02;
const UNW_FLAG_CHAININFO: u8 = 0x04;
/// Allowed flag combinations (KNONFLAGS | EHANDLER | UHANDLER | CHAININFO).
// GTO-H4-D: allowed flag combinations are ONLY {0,1,2,3,4}. CHAININFO
// (0x04) combined with EHANDLER/UHANDLER (0x05/0x06/0x07) is invalid on x64
// (a chain entry must not also carry its own handler) and must fail closed.
const ALLOWED_UNWIND_FLAGS: [u8; 5] = [
    0x00, // KNONFLAGS
    0x01, // EHANDLER
    0x02, // UHANDLER
    0x03, // EHANDLER|UHANDLER
    0x04, // CHAININFO
];

/// Classification of the exception data-directory tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionDirectoryStatus {
    /// DD (va,size) both non-zero — full positive observation.
    Present,
    /// DD tuple all zero — complete negative observation.
    Absent,
    /// va/size one zero one non-zero — blocker.
    PartialTuple,
    /// size exceeds the host usize / observation cap — blocker.
    SizeOverflow,
}

/// Per-entry classification of one `RUNTIME_FUNCTION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFunctionStatus {
    Valid,
    /// Begin/End/UnwindInfoRVA outside SizeOfImage — blocker.
    OutOfRange,
    /// BeginAddress >= EndAddress — blocker.
    BeginNotLessEnd,
    /// unwind info RVA + size out of bounds — blocker.
    UnwindInfoOutOfBounds,
    /// handler RVA not inside an executable section — blocker.
    HandlerOutsideExec,
    /// table or unwind info misaligned — blocker.
    Unaligned,
}

impl fmt::Display for RuntimeFunctionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Valid => "Valid",
            Self::OutOfRange => "OutOfRange",
            Self::BeginNotLessEnd => "BeginNotLessEnd",
            Self::UnwindInfoOutOfBounds => "UnwindInfoOutOfBounds",
            Self::HandlerOutsideExec => "HandlerOutsideExec",
            Self::Unaligned => "Unaligned",
        })
    }
}

/// One observed `RUNTIME_FUNCTION` entry (12 bytes on x64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFunctionObservation {
    pub index: u32,
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
    pub status: RuntimeFunctionStatus,
}

/// Classification of one UNWIND_INFO structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindInfoStatus {
    Valid,
    /// UNWIND_INFO.version > 2 on x64 — blocker (E9).
    InvalidVersion,
    /// flags bits outside the allowed combinations — blocker (E10).
    InvalidFlags,
    /// count_of_codes * 2 + 4 exceeds the unwind info span — blocker (E13).
    CodesOutOfBounds,
    /// chained unwind info RVA outside the image — blocker (E11).
    InvalidChain,
    /// EHANDLER/UHANDLER handler RVA outside executable sections — blocker (E12).
    HandlerOutsideExec,
    /// unwind info bytes could not be read — blocker.
    ShortRead,
}

impl fmt::Display for UnwindInfoStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Valid => "Valid",
            Self::InvalidVersion => "InvalidVersion",
            Self::InvalidFlags => "InvalidFlags",
            Self::CodesOutOfBounds => "CodesOutOfBounds",
            Self::InvalidChain => "InvalidChain",
            Self::HandlerOutsideExec => "HandlerOutsideExec",
            Self::ShortRead => "ShortRead",
        })
    }
}

/// Classification of one unwind code slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindCodeStatus {
    Valid,
    InvalidOp,
    InvalidVersion,
}

impl fmt::Display for UnwindCodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Valid => "Valid",
            Self::InvalidOp => "InvalidOp",
            Self::InvalidVersion => "InvalidVersion",
        })
    }
}

/// One `UNWIND_CODE` slot (2 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindCodeObservation {
    pub code_offset: u8,
    pub unwind_op: u8,
    pub op_info: u8,
    pub slot_status: UnwindCodeStatus,
}

/// Classification of one chained RUNTIME_FUNCTION (UNW_FLAG_CHAININFO tail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainInfoStatus {
    Valid,
    /// Begin/End/UnwindInfoAddress outside SizeOfImage — blocker.
    OutOfRange,
    /// BeginAddress >= EndAddress — blocker.
    BeginNotLessEnd,
    /// chained 12-byte tuple could not be fully read — blocker.
    ShortRead,
}

impl fmt::Display for ChainInfoStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Valid => "Valid",
            Self::OutOfRange => "OutOfRange",
            Self::BeginNotLessEnd => "BeginNotLessEnd",
            Self::ShortRead => "ShortRead",
        })
    }
}

/// One UNWIND_INFO structure observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindInfoObservation {
    pub function_index: u32,
    pub version: u8,
    pub flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub codes: Vec<UnwindCodeObservation>,
    /// Exception handler RVA (UNW_FLAG_EHANDLER|UHANDLER only).
    pub handler_rva: Option<u32>,
    /// Full chained RUNTIME_FUNCTION (UNW_FLAG_CHAININFO only) — a complete
    /// 12-byte tuple; never derived from/reusing handler_rva (P5).
    pub chain: Option<ChainInfoObservation>,
    pub status: UnwindInfoStatus,
}

/// The chained RUNTIME_FUNCTION tuple (BeginAddress/EndAddress/
/// UnwindInfoAddress) parsed from the UNW_FLAG_CHAININFO optional tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainInfoObservation {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
    pub status: ChainInfoStatus,
}

/// Complete runtime exception observation captured at the dump boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionObservationReport {
    pub directory_present: bool,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub pe32_plus: bool,
    pub runtime_image_base: u64,
    pub preferred_image_base: u64,
    pub size_of_image: u32,
    pub directory_bytes_read: usize,
    pub function_count: u32,
    pub functions: Vec<RuntimeFunctionObservation>,
    pub unwind_infos: Vec<UnwindInfoObservation>,
    /// Entries sorted by BeginAddress ascending.
    pub sorted_by_begin: bool,
    /// No illegal overlap between adjacent entries.
    pub no_overlap: bool,
    /// All handler RVAs inside executable sections.
    pub handlers_in_executable: bool,
    pub blockers: Vec<String>,
}

impl ExceptionObservationReport {
    /// No blockers and every entry valid.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.blockers.is_empty()
            && self
                .functions
                .iter()
                .all(|f| f.status == RuntimeFunctionStatus::Valid)
            && self
                .unwind_infos
                .iter()
                .all(|u| u.status == UnwindInfoStatus::Valid)
    }

    /// Single-line failure summary for diagnostics.
    #[must_use]
    pub fn failure_summary(&self) -> String {
        if self.is_complete() {
            return "complete".to_string();
        }
        let mut parts: Vec<String> = Vec::new();
        if !self.blockers.is_empty() {
            parts.push(format!("blockers={}", self.blockers.len()));
        }
        let bad_fns = self
            .functions
            .iter()
            .filter(|f| f.status != RuntimeFunctionStatus::Valid)
            .count();
        if bad_fns > 0 {
            parts.push(format!("bad_functions={bad_fns}"));
        }
        let bad_unw = self
            .unwind_infos
            .iter()
            .filter(|u| u.status != UnwindInfoStatus::Valid)
            .count();
        if bad_unw > 0 {
            parts.push(format!("bad_unwind={bad_unw}"));
        }
        parts.join("; ")
    }
}

/// Read an `IMAGE_RUNTIME_FUNCTION_ENTRY` from `bytes` (x64 layout).
#[allow(clippy::cast_possible_truncation)]
fn read_runtime_function(bytes: &[u8], offset: usize) -> Option<(u32, u32, u32)> {
    let b = bytes.get(offset..offset.checked_add(RUNTIME_FUNCTION_SIZE)?)?;
    Some((
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
    ))
}

/// Locate the executable-section index containing `rva`, if any.
fn executable_section_containing(pe: &PeHeader, rva: u32) -> Option<usize> {
    for (i, s) in pe.sections.iter().enumerate() {
        if s.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let va = s.header.virtual_address;
        let vs = s.header.virtual_size;
        let end = va.checked_add(vs)?;
        if rva >= va && rva < end {
            return Some(i);
        }
    }
    None
}

/// Read a byte from live process memory via `reader`.
fn read_byte_at<F, E>(address: u64, reader: &F) -> Result<u8, String>
where
    F: Fn(u64, &mut [u8]) -> Result<usize, E>,
    E: std::fmt::Display,
{
    let mut buf = [0u8; 1];
    let n = reader(address, &mut buf).map_err(|e| e.to_string())?;
    if n != 1 {
        return Err("short read".to_string());
    }
    Ok(buf[0])
}

/// Capture the runtime exception directory observation (immutable).
///
/// `reader` reads live process memory at a native address. `preferred_image_base`
/// is the on-disk PE base (the runtime `pe.image_base` may be the ASLR load
/// base) — passed explicitly so relocation image identity matches the PE
/// evidence (same convention as `relocation_observation`).
pub fn observe_exception_runtime<F, E>(
    pe: &PeHeader,
    runtime_image_base: u64,
    preferred_image_base: u64,
    reader: F,
) -> ExceptionObservationReport
where
    F: Fn(u64, &mut [u8]) -> Result<usize, E>,
    E: std::fmt::Display,
{
    let directory = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    let size_of_image = pe.size_of_image();
    let mut report = ExceptionObservationReport {
        directory_present: directory.virtual_address != 0 || directory.size != 0,
        directory_rva: directory.virtual_address,
        directory_size: directory.size,
        pe32_plus: pe.is_64bit,
        runtime_image_base,
        preferred_image_base,
        size_of_image,
        directory_bytes_read: 0,
        function_count: 0,
        functions: Vec::new(),
        unwind_infos: Vec::new(),
        sorted_by_begin: true,
        no_overlap: true,
        handlers_in_executable: true,
        blockers: Vec::new(),
    };

    // E1: tuple consistency.
    if (directory.virtual_address == 0) != (directory.size == 0) {
        report
            .blockers
            .push("exception data-directory is a partial (RVA,size) tuple".to_string());
        return report;
    }
    // N1 / E14: absent or present-but-empty directory — complete negative
    // observation, not a blocker (same semantics as TLS).
    if directory.virtual_address == 0 {
        return report;
    }
    if directory.size == 0 {
        report.directory_present = true;
        return report;
    }

    // E2: size fits usize and stays under the observation cap.
    let Ok(dir_size) = usize::try_from(directory.size) else {
        report
            .blockers
            .push("exception directory size does not fit host usize".to_string());
        return report;
    };
    if dir_size > MAX_EXCEPTION_DIRECTORY_BYTES {
        report
            .blockers
            .push(format!(
                "exception directory size {dir_size} exceeds observation cap {MAX_EXCEPTION_DIRECTORY_BYTES}"
            ));
        return report;
    }

    // E3: x64 RUNTIME_FUNCTION array is 12-byte aligned.
    if dir_size % RUNTIME_FUNCTION_SIZE != 0 {
        report.blockers.push(format!(
            "exception directory size {dir_size} is not a multiple of {RUNTIME_FUNCTION_SIZE}"
        ));
        return report;
    }

    // Directory range inside SizeOfImage.
    let Some(dir_end) = directory.virtual_address.checked_add(directory.size) else {
        report
            .blockers
            .push("exception directory range arithmetic overflow".to_string());
        return report;
    };
    if u64::from(dir_end) > u64::from(size_of_image) {
        report
            .blockers
            .push("exception directory range is outside SizeOfImage".to_string());
        return report;
    }

    // Read the directory bytes from live memory (runtime image base).
    let dir_va = u64::from(directory.virtual_address);
    let dir_address = runtime_image_base.checked_add(dir_va).unwrap_or(u64::MAX);
    let mut table = vec![0u8; dir_size];
    let read_result = reader(dir_address, &mut table);
    match read_result {
        Ok(n) if n == dir_size => {}
        Ok(n) => {
            report
                .blockers
                .push(format!("exception directory short read: {n}/{dir_size}"));
            return report;
        }
        Err(e) => {
            report
                .blockers
                .push(format!("exception directory read failed: {e}"));
            return report;
        }
    }
    report.directory_bytes_read = dir_size;
    report.function_count = (dir_size / RUNTIME_FUNCTION_SIZE) as u32;

    let entry_count = dir_size / RUNTIME_FUNCTION_SIZE;
    let mut prev_end: Option<u32> = None;
    for i in 0..entry_count {
        let offset = i * RUNTIME_FUNCTION_SIZE;
        let Some((begin, end, unwind_rva)) = read_runtime_function(&table, offset) else {
            report
                .blockers
                .push(format!("RUNTIME_FUNCTION[{i}] truncated"));
            continue;
        };
        let mut status = RuntimeFunctionStatus::Valid;

        // E5: all three fields inside SizeOfImage.
        if begin >= size_of_image || end > size_of_image || unwind_rva >= size_of_image {
            status = RuntimeFunctionStatus::OutOfRange;
        }
        // E4: BeginAddress < EndAddress.
        if status == RuntimeFunctionStatus::Valid && begin >= end {
            status = RuntimeFunctionStatus::BeginNotLessEnd;
        }
        // E6/E7: ordering and overlap (checked only while both valid).
        if status == RuntimeFunctionStatus::Valid {
            if let Some(pe_prev) = prev_end {
                if begin < pe_prev {
                    report.sorted_by_begin = false;
                    report.no_overlap = false;
                }
            }
        }
        if status == RuntimeFunctionStatus::Valid {
            prev_end = Some(end);
        }

        report.functions.push(RuntimeFunctionObservation {
            index: i as u32,
            begin_rva: begin,
            end_rva: end,
            unwind_info_rva: unwind_rva,
            status,
        });

        if status == RuntimeFunctionStatus::Valid {
            observe_unwind_info(
                pe,
                &mut report,
                i as u32,
                unwind_rva,
                runtime_image_base,
                &reader,
            );
        }
    }

    let bad_fn_count = report
        .functions
        .iter()
        .filter(|f| f.status != RuntimeFunctionStatus::Valid)
        .count();
    if bad_fn_count > 0 {
        report.blockers.push(format!(
            "{bad_fn_count} RUNTIME_FUNCTION entr{} invalid",
            if bad_fn_count == 1 { "y" } else { "ies" }
        ));
    }
    if !report.sorted_by_begin {
        report
            .blockers
            .push("RUNTIME_FUNCTION entries not sorted by BeginAddress".to_string());
    }
    if !report.no_overlap {
        report
            .blockers
            .push("RUNTIME_FUNCTION entries overlap".to_string());
    }
    if !report.handlers_in_executable {
        report
            .blockers
            .push("unwind handler RVA outside executable sections".to_string());
    }
    report
}

/// Observe one UNWIND_INFO structure (E8-E13).
#[allow(clippy::too_many_lines)]
fn observe_unwind_info<F, E>(
    pe: &PeHeader,
    report: &mut ExceptionObservationReport,
    function_index: u32,
    unwind_info_rva: u32,
    runtime_image_base: u64,
    reader: &F,
) where
    F: Fn(u64, &mut [u8]) -> Result<usize, E>,
    E: std::fmt::Display,
{
    let size_of_image = pe.size_of_image();
    // E8: unwind info RVA + header span inside SizeOfImage.
    let Some(info_end) = unwind_info_rva.checked_add(UNWIND_INFO_HEADER_SIZE as u32) else {
        report.unwind_infos.push(UnwindInfoObservation {
            function_index,
            version: 0,
            flags: 0,
            size_of_prolog: 0,
            count_of_codes: 0,
            frame_register: 0,
            frame_offset: 0,
            codes: Vec::new(),
            handler_rva: None,
            chain: None,
            status: UnwindInfoStatus::ShortRead,
        });
        report
            .blockers
            .push(format!("unwind info RVA {unwind_info_rva:#x} overflow"));
        return;
    };
    if info_end > size_of_image {
        report.unwind_infos.push(UnwindInfoObservation {
            function_index,
            version: 0,
            flags: 0,
            size_of_prolog: 0,
            count_of_codes: 0,
            frame_register: 0,
            frame_offset: 0,
            codes: Vec::new(),
            handler_rva: None,
            chain: None,
            status: UnwindInfoStatus::ShortRead,
        });
        report.blockers.push(format!(
            "unwind info RVA {unwind_info_rva:#x} out of bounds"
        ));
        return;
    }

    let ui_va = u64::from(unwind_info_rva);
    let addr = runtime_image_base.checked_add(ui_va).unwrap_or(u64::MAX);
    let mut header = [0u8; UNWIND_INFO_HEADER_SIZE];
    let header_ok = match reader(addr, &mut header) {
        Ok(n) => n == UNWIND_INFO_HEADER_SIZE,
        Err(e) => {
            report
                .blockers
                .push(format!("unwind info read failed: {e}"));
            false
        }
    };
    if !header_ok {
        report.unwind_infos.push(UnwindInfoObservation {
            function_index,
            version: 0,
            flags: 0,
            size_of_prolog: 0,
            count_of_codes: 0,
            frame_register: 0,
            frame_offset: 0,
            codes: Vec::new(),
            handler_rva: None,
            chain: None,
            status: UnwindInfoStatus::ShortRead,
        });
        return;
    }
    let version = header[0] & 0x07;
    let flags = header[0] >> 3;
    let size_of_prolog = header[1];
    let count_of_codes = header[2];
    let frame_register = header[3] & 0x0f;
    let frame_offset = header[3] >> 4;
    let mut status = UnwindInfoStatus::Valid;

    // E9: version <= 2 on x64.
    if version > 2 {
        status = UnwindInfoStatus::InvalidVersion;
    }
    // E10: flags within allowed combinations.
    if !ALLOWED_UNWIND_FLAGS.contains(&flags) {
        status = UnwindInfoStatus::InvalidFlags;
    }

    // E13: the unwind info span covers header + codes + 4-byte-aligned
    // padding (the optional handler slot sits on a 4-byte boundary after the
    // codes). count_of_codes is ODD for EHANDLER/UHANDLER/CHAININFO entries
    // (1 padding byte), EVEN for plain entries. The span is bounded by
    // SizeOfImage (E8); read codes within the image, then validate the bound.
    let code_bytes = u32::from(count_of_codes) * 2;
    let padded_bytes = align_up_4(code_bytes);
    // P5: the optional tail must be counted in the span: EHANDLER/UHANDLER
    // add 4 bytes (handler RVA); CHAININFO adds a full 12-byte RUNTIME_FUNCTION.
    let mut total = UNWIND_INFO_HEADER_SIZE as u32 + padded_bytes;
    if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        total = total.checked_add(4).unwrap_or(u32::MAX);
    }
    if flags & UNW_FLAG_CHAININFO != 0 {
        total = total
            .checked_add(RUNTIME_FUNCTION_SIZE as u32)
            .unwrap_or(u32::MAX);
    }
    let mut codes = Vec::with_capacity(usize::from(count_of_codes));
    let mut handler_rva: Option<u32> = None;
    let mut chain: Option<ChainInfoObservation> = None;
    let mut codes_valid = true;
    if u64::from(unwind_info_rva) + u64::from(total) > u64::from(size_of_image) {
        status = UnwindInfoStatus::CodesOutOfBounds;
        codes_valid = false;
    } else if status == UnwindInfoStatus::Valid {
        for c in 0..usize::from(count_of_codes) {
            let slot_addr = addr
                .checked_add(UNWIND_INFO_HEADER_SIZE as u64 + (c * 2) as u64)
                .unwrap_or(u64::MAX);
            let slot_hi = read_byte_at(slot_addr, reader).ok();
            let slot_lo = read_byte_at(slot_addr + 1, reader).ok();
            let (code_offset, unwind_op, op_info) = match (slot_hi, slot_lo) {
                (Some(hi), Some(lo)) => (hi, lo & 0x0f, lo >> 4),
                _ => {
                    codes_valid = false;
                    break;
                }
            };
            codes.push(UnwindCodeObservation {
                code_offset,
                unwind_op,
                op_info,
                slot_status: UnwindCodeStatus::Valid,
            });
        }
        // Optional tail after the codes, on the 4-byte-aligned boundary
        // (GTO-H4-D: the slot is at header + align_up(code_bytes, 4), NOT
        // header + code_bytes — odd count_of_codes leaves 1 padding byte).
        // P5: EHANDLER/UHANDLER read a 4-byte handler RVA; CHAININFO reads a
        // full 12-byte RUNTIME_FUNCTION (Begin/End/UnwindInfoAddress) — the
        // chain tuple is NEVER treated as a handler RVA.
        let tail_addr = addr
            .checked_add(UNWIND_INFO_HEADER_SIZE as u64 + padded_bytes as u64)
            .unwrap_or(u64::MAX);
        if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            let mut hbuf = [0u8; 4];
            if reader(tail_addr, &mut hbuf).is_ok_and(|n| n == 4) {
                handler_rva = Some(u32::from_le_bytes([hbuf[0], hbuf[1], hbuf[2], hbuf[3]]));
            }
        }
        if flags & UNW_FLAG_CHAININFO != 0 {
            let mut cbuf = [0u8; RUNTIME_FUNCTION_SIZE];
            let read_ok = reader(tail_addr, &mut cbuf).is_ok_and(|n| n == RUNTIME_FUNCTION_SIZE);
            if read_ok {
                let begin_address = u32::from_le_bytes([cbuf[0], cbuf[1], cbuf[2], cbuf[3]]);
                let end_address = u32::from_le_bytes([cbuf[4], cbuf[5], cbuf[6], cbuf[7]]);
                let unwind_info_address =
                    u32::from_le_bytes([cbuf[8], cbuf[9], cbuf[10], cbuf[11]]);
                let mut cstatus = ChainInfoStatus::Valid;
                if begin_address >= size_of_image
                    || end_address > size_of_image
                    || unwind_info_address >= size_of_image
                {
                    cstatus = ChainInfoStatus::OutOfRange;
                }
                if cstatus == ChainInfoStatus::Valid && begin_address >= end_address {
                    cstatus = ChainInfoStatus::BeginNotLessEnd;
                }
                chain = Some(ChainInfoObservation {
                    begin_address,
                    end_address,
                    unwind_info_address,
                    status: cstatus,
                });
            } else {
                chain = Some(ChainInfoObservation {
                    begin_address: 0,
                    end_address: 0,
                    unwind_info_address: 0,
                    status: ChainInfoStatus::ShortRead,
                });
            }
        }
    }
    if !codes_valid && status == UnwindInfoStatus::Valid {
        status = UnwindInfoStatus::CodesOutOfBounds;
    }

    // E11: CHAININFO chain tuple fully valid (read, in-image, Begin<End).
    if status == UnwindInfoStatus::Valid && flags & UNW_FLAG_CHAININFO != 0 {
        let bad = !chain
            .as_ref()
            .is_some_and(|c| c.status == ChainInfoStatus::Valid);
        if bad {
            status = UnwindInfoStatus::InvalidChain;
        }
    }
    // E12: EHANDLER/UHANDLER handler inside executable sections.
    if status == UnwindInfoStatus::Valid && flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        let Some(hrva) = handler_rva else {
            report.handlers_in_executable = false;
            report.unwind_infos.push(UnwindInfoObservation {
                function_index,
                version,
                flags,
                size_of_prolog,
                count_of_codes,
                frame_register,
                frame_offset,
                codes,
                handler_rva,
                chain,
                status: UnwindInfoStatus::HandlerOutsideExec,
            });
            return;
        };
        if executable_section_containing(pe, hrva).is_none() {
            status = UnwindInfoStatus::HandlerOutsideExec;
            report.handlers_in_executable = false;
        }
    }

    report.unwind_infos.push(UnwindInfoObservation {
        function_index,
        version,
        flags,
        size_of_prolog,
        count_of_codes,
        frame_register,
        frame_offset,
        codes,
        handler_rva,
        chain,
        status,
    });
}

/// True when the exception directory is present but not raw-backed by any
/// section (E15: force_pdata signal; reconstruction is the dump layer's job).
#[must_use]
pub fn exception_directory_lacks_raw(pe: &PeHeader, rva: u32, size: u32) -> bool {
    if rva == 0 || size == 0 {
        return false;
    }
    let Some(end) = rva.checked_add(size) else {
        return true;
    };
    for s in &pe.sections {
        let raw = s.header.size_of_raw_data;
        let ptr = s.header.pointer_to_raw_data;
        if raw == 0 || ptr == 0 {
            continue;
        }
        let va = s.header.virtual_address;
        let Some(raw_end) = va.checked_add(raw) else {
            continue;
        };
        if rva >= va && end <= raw_end {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pe(dd_va: u32, dd_size: u32, image_size: u32) -> PeHeader {
        let bytes = {
            let mut b = vec![0u8; 0x400];
            b[0] = b'M';
            b[1] = b'Z';
            b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            b[0x80..0x84].copy_from_slice(b"PE\0\0");
            b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
            b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // number of sections
            b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // size_of_optional_header (PE32+)
            b[0x98..0x9a].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+ magic (e_lfanew+4+20)
            b[0xd0..0xd4].copy_from_slice(&image_size.to_le_bytes()); // SizeOfImage (oh+56)
            let dd_off = 0x98 + 112 + 8 * 3; // exception data directory
            b[dd_off..dd_off + 4].copy_from_slice(&dd_va.to_le_bytes());
            b[dd_off + 4..dd_off + 8].copy_from_slice(&dd_size.to_le_bytes());
            b
        };
        PeHeader::from_bytes(&bytes).expect("test PE parses")
    }

    fn memory_reader(
        mem: &[u8],
        base: u64,
    ) -> impl Fn(u64, &mut [u8]) -> Result<usize, String> + '_ {
        move |address, buffer| {
            let off = usize::try_from(address.checked_sub(base).ok_or("below base")?)
                .map_err(|_| "usize".to_string())?;
            let Some(slice) = mem.get(off..off.checked_add(buffer.len()).ok_or("len")?) else {
                return Err("out of range".to_string());
            };
            buffer.copy_from_slice(slice);
            Ok(buffer.len())
        }
    }

    fn valid_table() -> Vec<u8> {
        // Two functions: [0x1000,0x1100) -> unwind 0x2000; [0x1100,0x1200) -> unwind 0x2010.
        let mut t = Vec::new();
        for (begin, end, uw) in [(0x1000u32, 0x1100u32, 0x2000u32), (0x1100, 0x1200, 0x2010)] {
            t.extend_from_slice(&begin.to_le_bytes());
            t.extend_from_slice(&end.to_le_bytes());
            t.extend_from_slice(&uw.to_le_bytes());
        }
        t
    }

    fn valid_unwind(version_flags: u8) -> Vec<u8> {
        // header: version/flags, prolog, codes=0, frame=0
        vec![version_flags, 0x10, 0x00, 0x00]
    }

    #[test]
    fn n1_exception_directory_absent_is_not_blocker() {
        let pe = test_pe(0, 0, 0x4000);
        let mem = vec![0u8; 0x100];
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.directory_present);
        assert!(
            report.is_complete(),
            "absent directory is a complete negative"
        );
        assert!(report.blockers.is_empty());
    }

    #[test]
    fn e1_partial_tuple_is_blocker() {
        let pe = test_pe(0x2000, 0, 0x4000);
        let mem = vec![0u8; 0x100];
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(report.blockers.iter().any(|b| b.contains("partial")));
    }

    #[test]
    fn e2_size_cap_is_blocker() {
        let pe = test_pe(0x1000, (MAX_EXCEPTION_DIRECTORY_BYTES + 1) as u32, 0x400000);
        let mem = vec![0u8; 0x100];
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(report.blockers.iter().any(|b| b.contains("cap")));
    }

    #[test]
    fn e3_size_not_multiple_of_12_is_blocker() {
        let pe = test_pe(0x1000, 4, 0x4000);
        let mem = vec![0u8; 0x100];
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(report.blockers.iter().any(|b| b.contains("multiple")));
    }

    #[test]
    fn e4_begin_not_less_end_is_blocker() {
        // entry begin == end
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&{
            let mut t = Vec::new();
            t.extend_from_slice(&0x1000u32.to_le_bytes());
            t.extend_from_slice(&0x1000u32.to_le_bytes()); // begin == end
            t.extend_from_slice(&0x2000u32.to_le_bytes());
            t
        });
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(report
            .functions
            .iter()
            .any(|f| f.status == RuntimeFunctionStatus::BeginNotLessEnd));
    }

    #[test]
    fn e5_out_of_range_is_blocker() {
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&{
            let mut t = Vec::new();
            t.extend_from_slice(&0x8000u32.to_le_bytes()); // > SizeOfImage
            t.extend_from_slice(&0x9000u32.to_le_bytes());
            t.extend_from_slice(&0x2000u32.to_le_bytes());
            t
        });
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(report
            .functions
            .iter()
            .any(|f| f.status == RuntimeFunctionStatus::OutOfRange));
    }

    #[test]
    fn e6_unsorted_entries_are_blocker() {
        let pe = test_pe(0x1000, 24, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        // unsorted: [0x1100..] before [0x1000..]
        mem[0x1000..0x1018].copy_from_slice(&{
            let mut t = Vec::new();
            for (begin, end, uw) in [(0x1100u32, 0x1200u32, 0x2000u32), (0x1000, 0x1100, 0x2010)] {
                t.extend_from_slice(&begin.to_le_bytes());
                t.extend_from_slice(&end.to_le_bytes());
                t.extend_from_slice(&uw.to_le_bytes());
            }
            t
        });
        mem[0x2000..0x2004].copy_from_slice(&valid_unwind(0));
        mem[0x2010..0x2014].copy_from_slice(&valid_unwind(0));
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(!report.sorted_by_begin);
        assert!(report.blockers.iter().any(|b| b.contains("sorted")));
    }

    #[test]
    fn e7_overlap_is_blocker() {
        let pe = test_pe(0x1000, 24, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        // overlap: [0x1000..0x1200] then [0x1100..0x1300]
        mem[0x1000..0x1018].copy_from_slice(&{
            let mut t = Vec::new();
            for (begin, end, uw) in [(0x1000u32, 0x1200u32, 0x2000u32), (0x1100, 0x1300, 0x2010)] {
                t.extend_from_slice(&begin.to_le_bytes());
                t.extend_from_slice(&end.to_le_bytes());
                t.extend_from_slice(&uw.to_le_bytes());
            }
            t
        });
        mem[0x2000..0x2004].copy_from_slice(&valid_unwind(0));
        mem[0x2010..0x2014].copy_from_slice(&valid_unwind(0));
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(!report.no_overlap);
    }

    #[test]
    fn e9_invalid_unwind_version_is_blocker() {
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&{
            let mut t = Vec::new();
            t.extend_from_slice(&0x1000u32.to_le_bytes());
            t.extend_from_slice(&0x1100u32.to_le_bytes());
            t.extend_from_slice(&0x2000u32.to_le_bytes());
            t
        });
        mem[0x2000..0x2004].copy_from_slice(&valid_unwind(0x07)); // version=7, flags=0
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(report
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::InvalidVersion));
    }

    #[test]
    fn e10_invalid_flags_are_blocker() {
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&{
            let mut t = Vec::new();
            t.extend_from_slice(&0x1000u32.to_le_bytes());
            t.extend_from_slice(&0x1100u32.to_le_bytes());
            t.extend_from_slice(&0x2000u32.to_le_bytes());
            t
        });
        mem[0x2000..0x2004].copy_from_slice(&valid_unwind(0x40)); // flags=8 (invalid: >7)
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(report
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::InvalidFlags));
    }

    #[test]
    fn e12_handler_outside_executable_is_blocker() {
        // PE with one executable .text section (0x1000..0x4000).
        let bytes = {
            let mut b = vec![0u8; 0x400];
            b[0] = b'M';
            b[1] = b'Z';
            b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            b[0x80..0x84].copy_from_slice(b"PE\0\0");
            b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
            b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // number of sections
            b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // size_of_optional_header
            b[0x98..0x9a].copy_from_slice(&0x020Bu16.to_le_bytes()); // magic
            b[0xd0..0xd4].copy_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
            let dd_off = 0x98 + 112 + 8 * 3;
            b[dd_off..dd_off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
            b[dd_off + 4..dd_off + 8].copy_from_slice(&12u32.to_le_bytes());
            let sec = 0x98 + 112 + 8 * 16;
            b[sec..sec + 8].copy_from_slice(b".text\0\0\0");
            b[sec + 8..sec + 12].copy_from_slice(&0x3000u32.to_le_bytes()); // virtual size
            b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
            b[sec + 16..sec + 20].copy_from_slice(&0x3000u32.to_le_bytes()); // raw size
            b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
            b[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // EXECUTE|READ
            b
        };
        let pe = PeHeader::from_bytes(&bytes).expect("test PE parses");
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&{
            let mut t = Vec::new();
            t.extend_from_slice(&0x1000u32.to_le_bytes());
            t.extend_from_slice(&0x1100u32.to_le_bytes());
            t.extend_from_slice(&0x2000u32.to_le_bytes());
            t
        });
        // unwind @0x2000: flags=EHANDLER(0x01<<3=0x08), 0 codes, handler at 0x4000 (outside exec)
        mem[0x2000] = 0x08; // version=0, flags=EHANDLER
        mem[0x2001] = 0x10;
        mem[0x2002] = 0x00;
        mem[0x2003] = 0x00;
        mem[0x2004..0x2008].copy_from_slice(&0x4000u32.to_le_bytes()); // handler outside exec
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(!report.handlers_in_executable);
        assert!(report
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::HandlerOutsideExec));
    }

    #[test]
    fn valid_table_complete() {
        let pe = test_pe(0x1000, 24, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x1018].copy_from_slice(&valid_table());
        mem[0x2000..0x2004].copy_from_slice(&valid_unwind(0));
        mem[0x2010..0x2014].copy_from_slice(&valid_unwind(0));
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(report.is_complete(), "{}", report.failure_summary());
        assert_eq!(report.function_count, 2);
        assert_eq!(report.functions.len(), 2);
        assert_eq!(report.unwind_infos.len(), 2);
        assert!(report.sorted_by_begin);
        assert!(report.no_overlap);
        assert!(report.handlers_in_executable);
        assert!(report.blockers.is_empty());
    }

    // GTO-H4-D P4: fn78 regression — odd count_of_codes (13) places the
    // handler slot at header + align_up(26,4)=+28 (i.e. byte 32), NOT at
    // header+26 (byte 30). The defect read 0x6ee80000 (misaligned garbage);
    // the fixed parser reads 0x00106ee8 (executable-section handler).
    #[test]
    fn h4d_odd_count_of_codes_handler_alignment_fn78_regression() {
        // PE with one executable .text section (0x1000..0x5000).
        let bytes = {
            let mut b = vec![0u8; 0x400];
            b[0] = b'M';
            b[1] = b'Z';
            b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            b[0x80..0x84].copy_from_slice(b"PE  ");
            b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
            b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
            b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
            b[0x98..0x9a].copy_from_slice(&0x020Bu16.to_le_bytes());
            b[0xd0..0xd4].copy_from_slice(&0x6000u32.to_le_bytes());
            let dd_off = 0x98 + 112 + 8 * 3;
            b[dd_off..dd_off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
            b[dd_off + 4..dd_off + 8].copy_from_slice(&12u32.to_le_bytes());
            let sec = 0x98 + 112 + 8 * 16;
            b[sec..sec + 8].copy_from_slice(b".text   ");
            b[sec + 8..sec + 12].copy_from_slice(&0x4000u32.to_le_bytes());
            b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
            b[sec + 16..sec + 20].copy_from_slice(&0x4000u32.to_le_bytes());
            b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
            b[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
            b
        };
        let pe = PeHeader::from_bytes(&bytes).expect("test PE parses");
        let mut mem = vec![0u8; 0x6000];
        mem[0x1000..0x100c].copy_from_slice(&{
            let mut t = Vec::new();
            t.extend_from_slice(&0x1000u32.to_le_bytes());
            t.extend_from_slice(&0x1100u32.to_le_bytes());
            t.extend_from_slice(&0x2000u32.to_le_bytes());
            t
        });
        // unwind @0x2000: flags=EHANDLER (0x08 in the version/flags byte),
        // count_of_codes=13 (odd) — the exact fn78 shape.
        mem[0x2000] = 0x08; // version=0, flags=EHANDLER
        mem[0x2001] = 0x10; // size_of_prolog
        mem[0x2002] = 13; // count_of_codes = 13 (odd)
        mem[0x2003] = 0x00; // frame
                            // 13 unwind codes = 26 bytes at 0x2004..0x201e, then 2 padding
                            // bytes 0x201e..0x2020, then the handler slot at 0x2020..0x2024.
        for i in 0..13u32 {
            mem[(0x2004 + i * 2) as usize] = (i & 0xff) as u8;
            mem[(0x2004 + i * 2 + 1) as usize] = 0x00;
        }
        // Padding bytes 0x201e..0x2020 are part of the codes span, NOT the
        // handler. The pre-fix parser read the handler at 0x201e..0x2022
        // (header+26): those bytes are 0xcc 0x00 0x00 0x00 -> garbage
        // 0x000000cc. The fixed parser reads the aligned slot at 0x2020.
        mem[0x201e] = 0xcc;
        mem[0x201f] = 0x00;
        // handler slot @0x2020 = 0x0000_3000 (inside .text 0x1000..0x5000)
        mem[0x2020..0x2024].copy_from_slice(&0x0000_3000u32.to_le_bytes());
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(
            report.is_complete(),
            "{} statuses={:?}",
            report.failure_summary(),
            report
                .unwind_infos
                .iter()
                .map(|u| u.status)
                .collect::<Vec<_>>()
        );
        let u = &report.unwind_infos[0];
        assert_eq!(
            u.handler_rva,
            Some(0x0000_3000),
            "handler must be the aligned slot"
        );
        assert_eq!(u.status, UnwindInfoStatus::Valid);
        assert!(report.handlers_in_executable);
    }

    // GTO-H4-D P4: even count_of_codes has NO padding — the handler slot
    // sits directly after the codes (header + align_up(2n,4) == header+2n).
    #[test]
    fn h4d_even_count_of_codes_handler_no_padding() {
        // PE with one executable .text section (0x1000..0x5000).
        let bytes = {
            let mut b = vec![0u8; 0x400];
            b[0] = b'M';
            b[1] = b'Z';
            b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            b[0x80..0x84].copy_from_slice(b"PE  ");
            b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
            b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
            b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
            b[0x98..0x9a].copy_from_slice(&0x020Bu16.to_le_bytes());
            b[0xd0..0xd4].copy_from_slice(&0x6000u32.to_le_bytes());
            let dd_off = 0x98 + 112 + 8 * 3;
            b[dd_off..dd_off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
            b[dd_off + 4..dd_off + 8].copy_from_slice(&12u32.to_le_bytes());
            let sec = 0x98 + 112 + 8 * 16;
            b[sec..sec + 8].copy_from_slice(b".text   ");
            b[sec + 8..sec + 12].copy_from_slice(&0x4000u32.to_le_bytes());
            b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
            b[sec + 16..sec + 20].copy_from_slice(&0x4000u32.to_le_bytes());
            b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
            b[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
            b
        };
        let pe = PeHeader::from_bytes(&bytes).expect("test PE parses");
        let mut mem = vec![0u8; 0x6000];
        mem[0x1000..0x100c].copy_from_slice(&{
            let mut t = Vec::new();
            t.extend_from_slice(&0x1000u32.to_le_bytes());
            t.extend_from_slice(&0x1100u32.to_le_bytes());
            t.extend_from_slice(&0x2000u32.to_le_bytes());
            t
        });
        // unwind @0x2000: flags=EHANDLER, count=4 (even) — handler at
        // header+align_up(8,4)=header+8 = 0x200c (NO padding).
        mem[0x2000] = 0x08;
        mem[0x2001] = 0x10;
        mem[0x2002] = 4;
        mem[0x2003] = 0x00;
        for i in 0..4u32 {
            mem[(0x2004 + i * 2) as usize] = (i & 0xff) as u8;
            mem[(0x2004 + i * 2 + 1) as usize] = 0x00;
        }
        // handler slot @0x200c (4 codes * 2 = 8 bytes, aligned is 8)
        mem[0x200c..0x2010].copy_from_slice(&0x2000u32.to_le_bytes());
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(report.is_complete(), "{}", report.failure_summary());
        assert_eq!(report.unwind_infos[0].handler_rva, Some(0x2000));
        assert!(report.handlers_in_executable);
    }

    #[test]
    fn h4d_chaininfo_with_handler_is_invalid_flags() {
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&{
            let mut t = Vec::new();
            t.extend_from_slice(&0x1000u32.to_le_bytes());
            t.extend_from_slice(&0x1100u32.to_le_bytes());
            t.extend_from_slice(&0x2000u32.to_le_bytes());
            t
        });
        // version=1 (low 3 bits), flags=CHAININFO|EHANDLER=0x05 (bits 3..5)
        // => header[0] = (0x05 << 3) | 0x01 = 0x29.
        mem[0x2000] = 0x29; // version=1, flags=0x05 (CHAININFO|EHANDLER)
        mem[0x2001] = 0x10;
        mem[0x2002] = 0;
        mem[0x2003] = 0;
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete());
        assert!(report
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::InvalidFlags));
    }

    // GTO-H4-D-P5: UNWIND_CODE field order must be byte[0]=CodeOffset,
    // byte[1] low nibble=UnwindOp, byte[1] high nibble=OpInfo.
    #[test]
    fn p5_unwind_code_field_order() {
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&valid_table_1());
        mem[0x2000..0x2004].copy_from_slice(&[0x00, 0x10, 0x01, 0x00]); // 1 code
                                                                        // slot: byte[0]=0x05 (CodeOffset), byte[1]=0x42 (UnwindOp=2, OpInfo=4)
        mem[0x2004] = 0x05;
        mem[0x2005] = 0x42;
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(report.is_complete(), "{}", report.failure_summary());
        let c = &report.unwind_infos[0].codes[0];
        assert_eq!(c.code_offset, 0x05, "CodeOffset = byte[0]");
        assert_eq!(c.unwind_op, 0x02, "UnwindOp = byte[1] low nibble");
        assert_eq!(c.op_info, 0x04, "OpInfo = byte[1] high nibble");
    }

    // GTO-H4-D-P5: CHAININFO parses a full 12-byte RUNTIME_FUNCTION tail.
    #[test]
    fn p5_chaininfo_full_12_byte_tuple() {
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&valid_table_1());
        mem[0x2000] = 0x04 << 3; // flags=CHAININFO
        mem[0x2001] = 0x10;
        mem[0x2002] = 0x00; // 0 codes
        mem[0x2003] = 0x00;
        // 12-byte chain tuple @0x2004
        mem[0x2004..0x2008].copy_from_slice(&0x1000u32.to_le_bytes()); // Begin
        mem[0x2008..0x200c].copy_from_slice(&0x1100u32.to_le_bytes()); // End
        mem[0x200c..0x2010].copy_from_slice(&0x2000u32.to_le_bytes()); // UnwindInfoAddress
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(report.is_complete(), "{}", report.failure_summary());
        let u = &report.unwind_infos[0];
        assert_eq!(u.status, UnwindInfoStatus::Valid);
        let c = u.chain.as_ref().expect("chain parsed");
        assert_eq!(c.status, ChainInfoStatus::Valid);
        assert_eq!(c.begin_address, 0x1000);
        assert_eq!(c.end_address, 0x1100);
        assert_eq!(c.unwind_info_address, 0x2000);
        assert_eq!(u.handler_rva, None, "chain must not populate handler_rva");
    }

    // GTO-H4-D-P5: CHAININFO tail truncated (12B -> 4B) is fail-closed.
    #[test]
    fn p5_chaininfo_tail_truncated_fails_closed() {
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0xccu8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&valid_table_1());
        mem[0x2000] = 0x04 << 3; // flags=CHAININFO
        mem[0x2001] = 0x10;
        mem[0x2002] = 0x00;
        mem[0x2003] = 0x00;
        // Only 4 bytes of the 12-byte tail exist (rest is beyond SizeOfImage
        // boundary at 0x4000) — memory_reader fails on the full 12-byte read.
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete(), "truncated chain must fail closed");
        assert!(report
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::InvalidChain));
    }

    // GTO-H4-D-P5: CHAININFO Begin >= End is fail-closed.
    #[test]
    fn p5_chaininfo_begin_not_less_end_fails_closed() {
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&valid_table_1());
        mem[0x2000] = 0x04 << 3;
        mem[0x2001] = 0x10;
        mem[0x2002] = 0x00;
        mem[0x2003] = 0x00;
        mem[0x2004..0x2008].copy_from_slice(&0x1100u32.to_le_bytes()); // Begin >= End
        mem[0x2008..0x200c].copy_from_slice(&0x1100u32.to_le_bytes());
        mem[0x200c..0x2010].copy_from_slice(&0x2000u32.to_le_bytes());
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete(), "Begin>=End chain must fail closed");
        assert!(report
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::InvalidChain));
    }

    // GTO-H4-D-P5: CHAININFO RVA out of image is fail-closed.
    #[test]
    fn p5_chaininfo_rva_out_of_image_fails_closed() {
        let pe = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0u8; 0x5000];
        mem[0x1000..0x100c].copy_from_slice(&valid_table_1());
        mem[0x2000] = 0x04 << 3;
        mem[0x2001] = 0x10;
        mem[0x2002] = 0x00;
        mem[0x2003] = 0x00;
        mem[0x2004..0x2008].copy_from_slice(&0x1000u32.to_le_bytes());
        mem[0x2008..0x200c].copy_from_slice(&0x1100u32.to_le_bytes());
        mem[0x200c..0x2010].copy_from_slice(&0x8000u32.to_le_bytes()); // out of image
        let report = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(!report.is_complete(), "out-of-image chain must fail closed");
        assert!(report
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::InvalidChain));
    }

    // GTO-H4-D-P5: EHANDLER tail truncated (4B beyond image) is fail-closed.
    #[test]
    fn p5_eh_handler_tail_truncated_fails_closed() {
        let _pe2 = test_pe(0x1000, 12, 0x4000);
        let mut mem = vec![0xccu8; 0x4000];
        // unwind at 0x3ffc: header + 4-byte handler crosses SizeOfImage.
        mem[0x3ffc] = 0x01 << 3;
        mem[0x3ffd] = 0x10;
        mem[0x3ffe] = 0x00;
        mem[0x3fff] = 0x00;
        let pe2 = test_pe(0x1000, 12, 0x4000);
        let mut t = Vec::new();
        t.extend_from_slice(&0x1000u32.to_le_bytes());
        t.extend_from_slice(&0x1100u32.to_le_bytes());
        t.extend_from_slice(&0x3ffcu32.to_le_bytes());
        mem[0x1000..0x100c].copy_from_slice(&t);
        let report = observe_exception_runtime(
            &pe2,
            0x140000000,
            0x140000000,
            memory_reader(&mem, 0x140000000),
        );
        assert!(
            !report.is_complete(),
            "truncated EH handler must fail closed"
        );
        assert!(report
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::CodesOutOfBounds));
    }

    fn valid_table_1() -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&0x1000u32.to_le_bytes());
        t.extend_from_slice(&0x1100u32.to_le_bytes());
        t.extend_from_slice(&0x2000u32.to_le_bytes());
        t
    }

    #[test]
    fn exception_directory_lacks_raw_checks() {
        let bytes = {
            let mut b = vec![0u8; 0x400];
            b[0] = b'M';
            b[1] = b'Z';
            b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            b[0x80..0x84].copy_from_slice(b"PE\0\0");
            b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
            b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // number of sections
            b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // size_of_optional_header
            b[0x98..0x9a].copy_from_slice(&0x020Bu16.to_le_bytes()); // magic
            b[0xd0..0xd4].copy_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
            let sec = 0x98 + 112 + 8 * 16;
            b[sec..sec + 8].copy_from_slice(b".pdata\0\0");
            b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
            b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
            b[sec + 16..sec + 20].copy_from_slice(&0x1000u32.to_le_bytes());
            b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
            b
        };
        let pe = PeHeader::from_bytes(&bytes).expect("parses");
        // Covered range -> false.
        assert!(!exception_directory_lacks_raw(&pe, 0x1000, 0x800));
        // Uncovered range -> true.
        assert!(exception_directory_lacks_raw(&pe, 0x3000, 0x100));
        // Zero tuple -> false.
        assert!(!exception_directory_lacks_raw(&pe, 0, 0));
    }
}
