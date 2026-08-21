//! Independent final exception-directory decoder (GTO-H4-D D3).
//!
//! Parses a candidate PE's exception data-directory (`.pdata`) from its raw
//! bytes — a fresh reparse that never reuses dump-stage parsed objects.
//! The result is compared field-by-field against the runtime observation for
//! preservation evidence.

use crate::exception_observation::{
    ChainInfoObservation, ChainInfoStatus, ExceptionObservationReport, RuntimeFunctionObservation,
    RuntimeFunctionStatus, UnwindCodeObservation, UnwindCodeStatus, UnwindInfoObservation,
    UnwindInfoStatus, RUNTIME_FUNCTION_SIZE, UNWIND_INFO_HEADER_SIZE,
};
use crate::header::PeHeader;

/// IMAGE_SCN_MEM_EXECUTE.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// UNW_FLAG_* bits.
const UNW_FLAG_EHANDLER: u8 = 0x01;
const UNW_FLAG_UHANDLER: u8 = 0x02;
const UNW_FLAG_CHAININFO: u8 = 0x04;
/// Maximum exception directory bytes decoded from a candidate.
const MAX_EXCEPTION_DIRECTORY_BYTES: usize = 64 * 1024 * 1024;

/// Final exception-directory report decoded from candidate bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionFinalReport {
    pub directory_present: bool,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub pe32_plus: bool,
    pub image_base: u64,
    pub size_of_image: u32,
    pub directory_raw_offset: Option<u64>,
    pub directory_raw_backed: bool,
    pub function_count: u32,
    pub functions: Vec<RuntimeFunctionObservation>,
    pub unwind_infos: Vec<UnwindInfoObservation>,
    pub sorted_by_begin: bool,
    pub no_overlap: bool,
    pub handlers_in_executable: bool,
    pub blockers: Vec<String>,
}

impl ExceptionFinalReport {
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
}

/// Independent decoder: parse the exception directory from candidate bytes.
#[derive(Debug, Clone)]
pub struct ExceptionFinalDecoder {
    pe: PeHeader,
    bytes: Vec<u8>,
}

impl ExceptionFinalDecoder {
    /// Parse candidate PE headers from raw bytes (fresh reparse).
    pub fn from_candidate_bytes(bytes: &[u8]) -> Result<Self, String> {
        let pe = PeHeader::from_bytes(bytes).map_err(|e| format!("parse candidate PE: {e}"))?;
        Ok(Self {
            pe,
            bytes: bytes.to_vec(),
        })
    }

    /// Decode the exception directory from the candidate's raw bytes.
    pub fn decode(&self) -> ExceptionFinalReport {
        let directory = self.pe.nt_headers.optional_header.data_directory
            [crate::exception_observation::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        let size_of_image = self.pe.size_of_image();
        let mut report = ExceptionFinalReport {
            directory_present: directory.virtual_address != 0 || directory.size != 0,
            directory_rva: directory.virtual_address,
            directory_size: directory.size,
            pe32_plus: self.pe.is_64bit,
            image_base: self.pe.image_base,
            size_of_image,
            directory_raw_offset: None,
            directory_raw_backed: false,
            function_count: 0,
            functions: Vec::new(),
            unwind_infos: Vec::new(),
            sorted_by_begin: true,
            no_overlap: true,
            handlers_in_executable: true,
            blockers: Vec::new(),
        };

        if (directory.virtual_address == 0) != (directory.size == 0) {
            report
                .blockers
                .push("exception data-directory is a partial (RVA,size) tuple".to_string());
            return report;
        }
        if directory.virtual_address == 0 {
            return report;
        }
        if directory.size == 0 {
            report.directory_present = true;
            return report;
        }

        let Ok(dir_size) = usize::try_from(directory.size) else {
            report
                .blockers
                .push("exception directory size does not fit host usize".to_string());
            return report;
        };
        if dir_size > MAX_EXCEPTION_DIRECTORY_BYTES {
            report
                .blockers
                .push("exception directory size exceeds decode cap".to_string());
            return report;
        }
        if dir_size % RUNTIME_FUNCTION_SIZE != 0 {
            report.blockers.push(format!(
                "exception directory size {dir_size} is not a multiple of {RUNTIME_FUNCTION_SIZE}"
            ));
            return report;
        }

        // Raw backing check: the directory range must be fully covered by a
        // section's raw span in the candidate file.
        let Some(raw_off) = self.raw_span(directory.virtual_address, directory.size) else {
            report
                .blockers
                .push("exception directory is not exactly raw-backed".to_string());
            return report;
        };
        report.directory_raw_offset = Some(raw_off as u64);
        report.directory_raw_backed = true;

        let Some(end_off) = raw_off.checked_add(dir_size) else {
            report
                .blockers
                .push("exception directory offset arithmetic overflow".to_string());
            return report;
        };
        let Some(table) = self.bytes.get(raw_off..end_off) else {
            report
                .blockers
                .push("exception directory bytes are truncated".to_string());
            return report;
        };

        report.function_count = (dir_size / RUNTIME_FUNCTION_SIZE) as u32;
        let entry_count = dir_size / RUNTIME_FUNCTION_SIZE;
        let mut prev_end: Option<u32> = None;
        for i in 0..entry_count {
            let off = i * RUNTIME_FUNCTION_SIZE;
            let Some(entry) = table.get(off..off + RUNTIME_FUNCTION_SIZE) else {
                report
                    .blockers
                    .push(format!("RUNTIME_FUNCTION[{i}] truncated"));
                continue;
            };
            let begin = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let end = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            let unwind_rva = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
            let mut status = RuntimeFunctionStatus::Valid;

            if begin >= size_of_image || end > size_of_image || unwind_rva >= size_of_image {
                status = RuntimeFunctionStatus::OutOfRange;
            }
            if status == RuntimeFunctionStatus::Valid && begin >= end {
                status = RuntimeFunctionStatus::BeginNotLessEnd;
            }
            if status == RuntimeFunctionStatus::Valid {
                if let Some(pe_prev) = prev_end {
                    if begin < pe_prev {
                        report.sorted_by_begin = false;
                        report.no_overlap = false;
                    }
                }
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
                self.decode_unwind_info(&mut report, i as u32, unwind_rva);
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

    fn decode_unwind_info(
        &self,
        report: &mut ExceptionFinalReport,
        function_index: u32,
        unwind_info_rva: u32,
    ) {
        let size_of_image = self.pe.size_of_image();
        let Some(info_end) = unwind_info_rva.checked_add(UNWIND_INFO_HEADER_SIZE as u32) else {
            report
                .blockers
                .push(format!("unwind info RVA {unwind_info_rva:#x} overflow"));
            return;
        };
        if info_end > size_of_image {
            report.blockers.push(format!(
                "unwind info RVA {unwind_info_rva:#x} out of bounds"
            ));
            return;
        }
        let Some(header_off) = self.raw_span(unwind_info_rva, UNWIND_INFO_HEADER_SIZE as u32)
        else {
            report.blockers.push(format!(
                "unwind info RVA {unwind_info_rva:#x} not raw-backed"
            ));
            return;
        };
        let Some(header) = self
            .bytes
            .get(header_off..header_off + UNWIND_INFO_HEADER_SIZE)
        else {
            report
                .blockers
                .push(format!("unwind info RVA {unwind_info_rva:#x} truncated"));
            return;
        };
        let version = header[0] & 0x07;
        let flags = header[0] >> 3;
        let size_of_prolog = header[1];
        let count_of_codes = header[2];
        let frame_register = header[3] & 0x0f;
        let frame_offset = header[3] >> 4;
        let mut status = UnwindInfoStatus::Valid;

        if version > 2 {
            status = UnwindInfoStatus::InvalidVersion;
        }
        // GTO-H4-D: only {0,1,2,3,4} are allowed; CHAININFO+handler combos
        // (0x05/0x06/0x07) are invalid on x64 and must fail closed.
        if !matches!(flags, 0x00 | 0x01 | 0x02 | 0x03 | 0x04) {
            status = UnwindInfoStatus::InvalidFlags;
        }

        let code_bytes = u32::from(count_of_codes) * 2;
        // GTO-H4-D: the handler slot sits on the 4-byte-aligned boundary
        // after the codes (odd count_of_codes leaves 1 padding byte).
        let padded_bytes = (code_bytes + 3) & !3;
        // P5: the optional tail must be counted in the span: EHANDLER/UHANDLER
        // add 4 bytes (handler RVA); CHAININFO adds a full 12-byte
        // RUNTIME_FUNCTION. A truncated tail is CodesOutOfBounds (fail-closed).
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
        if u64::from(unwind_info_rva) + u64::from(total) > u64::from(size_of_image) {
            status = UnwindInfoStatus::CodesOutOfBounds;
        } else if status == UnwindInfoStatus::Valid {
            // P5: the FULL span (header + codes + optional tail) must be
            // raw-backed by one section — a truncated tail must not decode.
            let Some(off) = self.raw_span(unwind_info_rva, total) else {
                status = UnwindInfoStatus::CodesOutOfBounds;
                report.blockers.push(format!(
                    "unwind info RVA {unwind_info_rva:#x} span {total} not fully raw-backed"
                ));
                let codes_off = header_off + UNWIND_INFO_HEADER_SIZE;
                let _ = codes_off;
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
                return;
            };
            let codes_off = off + UNWIND_INFO_HEADER_SIZE;
            let codes_end = codes_off + code_bytes as usize;
            if let Some(slots) = self.bytes.get(codes_off..codes_end) {
                for c in 0..usize::from(count_of_codes) {
                    // P5: UNWIND_CODE is byte[0]=CodeOffset, byte[1] low
                    // nibble=UnwindOp, byte[1] high nibble=OpInfo — must match
                    // the runtime observer exactly (field-order parity).
                    let lo = slots[c * 2];
                    let hi = slots[c * 2 + 1];
                    codes.push(UnwindCodeObservation {
                        code_offset: lo,
                        unwind_op: hi & 0x0f,
                        op_info: hi >> 4,
                        slot_status: UnwindCodeStatus::Valid,
                    });
                }
            } else {
                status = UnwindInfoStatus::CodesOutOfBounds;
            }
            // Optional tail after the codes, 4-byte-aligned (GTO-H4-D).
            // P5: EHANDLER/UHANDLER read a 4-byte handler RVA; CHAININFO reads
            // a full 12-byte RUNTIME_FUNCTION — never reused as a handler RVA.
            let tail_off = codes_off + padded_bytes as usize;
            if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
                if let Some(hb) = self.bytes.get(tail_off..tail_off + 4) {
                    handler_rva = Some(u32::from_le_bytes([hb[0], hb[1], hb[2], hb[3]]));
                }
            }
            if flags & UNW_FLAG_CHAININFO != 0 {
                if let Some(cb) = self.bytes.get(tail_off..tail_off + RUNTIME_FUNCTION_SIZE) {
                    let begin_address = u32::from_le_bytes([cb[0], cb[1], cb[2], cb[3]]);
                    let end_address = u32::from_le_bytes([cb[4], cb[5], cb[6], cb[7]]);
                    let unwind_info_address = u32::from_le_bytes([cb[8], cb[9], cb[10], cb[11]]);
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

        if status == UnwindInfoStatus::Valid && flags & UNW_FLAG_CHAININFO != 0 {
            let bad = !chain
                .as_ref()
                .is_some_and(|c| c.status == ChainInfoStatus::Valid);
            if bad {
                status = UnwindInfoStatus::InvalidChain;
            }
        }
        if status == UnwindInfoStatus::Valid && flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0
        {
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
            if self.executable_section_containing(hrva).is_none() {
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

    /// Raw file offset of `[rva, rva+size)` when fully raw-backed by one
    /// section; `None` otherwise.
    fn raw_span(&self, rva: u32, size: u32) -> Option<usize> {
        let end = rva.checked_add(size)?;
        for s in &self.pe.sections {
            let raw = s.header.size_of_raw_data;
            let ptr = s.header.pointer_to_raw_data;
            if raw == 0 || ptr == 0 {
                continue;
            }
            let va = s.header.virtual_address;
            let raw_end = va.checked_add(raw)?;
            if rva >= va && end <= raw_end {
                let delta = rva - va;
                return Some(ptr as usize + delta as usize);
            }
        }
        None
    }

    fn executable_section_containing(&self, rva: u32) -> Option<usize> {
        for (i, s) in self.pe.sections.iter().enumerate() {
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
}

/// Field-by-field preservation comparison: runtime observation vs final decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionPreservationComparison {
    pub all_preserved: bool,
    pub directory_present_preserved: bool,
    pub directory_rva_preserved: bool,
    pub directory_size_preserved: bool,
    pub function_count_preserved: bool,
    pub functions_preserved: bool,
    pub unwind_infos_preserved: bool,
    pub blockers: Vec<String>,
}

/// Compare the runtime observation against the final decode. The comparison
/// is conservative: any field mismatch is a blocker (fail-closed).
#[must_use]
pub fn compare_runtime_final(
    runtime: &ExceptionObservationReport,
    final_report: &ExceptionFinalReport,
) -> ExceptionPreservationComparison {
    let mut c = ExceptionPreservationComparison {
        all_preserved: true,
        directory_present_preserved: runtime.directory_present == final_report.directory_present,
        directory_rva_preserved: runtime.directory_rva == final_report.directory_rva,
        directory_size_preserved: runtime.directory_size == final_report.directory_size,
        function_count_preserved: runtime.function_count == final_report.function_count,
        functions_preserved: runtime.functions == final_report.functions,
        unwind_infos_preserved: runtime.unwind_infos == final_report.unwind_infos,
        blockers: Vec::new(),
    };
    if !c.directory_present_preserved {
        c.blockers
            .push("exception directory presence mismatch".to_string());
    }
    if !c.directory_rva_preserved {
        c.blockers
            .push("exception directory RVA mismatch".to_string());
    }
    if !c.directory_size_preserved {
        c.blockers
            .push("exception directory size mismatch".to_string());
    }
    if !c.function_count_preserved {
        c.blockers
            .push("RUNTIME_FUNCTION count mismatch".to_string());
    }
    if !c.functions_preserved {
        c.blockers
            .push("RUNTIME_FUNCTION table mismatch".to_string());
    }
    if !c.unwind_infos_preserved {
        c.blockers.push("UNWIND_INFO mismatch".to_string());
    }
    c.all_preserved = c.blockers.is_empty();
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_with_pdata(
        pdata_rva: u32,
        pdata_size: u32,
        func_begin: u32,
        func_end: u32,
        unwind_rva: u32,
        text_begin: u32,
        text_end: u32,
    ) -> Vec<u8> {
        let mut b = vec![0u8; 0x6000];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        b[0x98..0x9a].copy_from_slice(&0x020Bu16.to_le_bytes());
        b[0xa0..0xa8].copy_from_slice(&0x140000000u64.to_le_bytes());
        b[0xd0..0xd4].copy_from_slice(&0x8000u32.to_le_bytes());
        let dd_off = 0x98 + 112 + 8 * 3;
        b[dd_off..dd_off + 4].copy_from_slice(&pdata_rva.to_le_bytes());
        b[dd_off + 4..dd_off + 8].copy_from_slice(&pdata_size.to_le_bytes());
        let sec = 0x98 + 112 + 8 * 16;
        b[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        b[sec + 8..sec + 12].copy_from_slice(&(text_end - text_begin).to_le_bytes());
        b[sec + 12..sec + 16].copy_from_slice(&text_begin.to_le_bytes());
        b[sec + 16..sec + 20].copy_from_slice(&(text_end - text_begin).to_le_bytes());
        b[sec + 20..sec + 24].copy_from_slice(&text_begin.to_le_bytes());
        b[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let sec2 = sec + 40;
        b[sec2..sec2 + 8].copy_from_slice(b".pdata\0\0");
        b[sec2 + 8..sec2 + 12].copy_from_slice(&pdata_size.to_le_bytes());
        b[sec2 + 12..sec2 + 16].copy_from_slice(&pdata_rva.to_le_bytes());
        b[sec2 + 16..sec2 + 20].copy_from_slice(&pdata_size.to_le_bytes());
        b[sec2 + 20..sec2 + 24].copy_from_slice(&pdata_rva.to_le_bytes());
        b[sec2 + 36..sec2 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
        let rf = pdata_rva as usize;
        b[rf..rf + 4].copy_from_slice(&func_begin.to_le_bytes());
        b[rf + 4..rf + 8].copy_from_slice(&func_end.to_le_bytes());
        b[rf + 8..rf + 12].copy_from_slice(&unwind_rva.to_le_bytes());
        b
    }

    fn decode_unwind(bytes: &[u8]) -> ExceptionFinalReport {
        ExceptionFinalDecoder::from_candidate_bytes(bytes)
            .expect("candidate parses")
            .decode()
    }

    #[test]
    fn h4d_final_odd_count_of_codes_handler_alignment() {
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        b[0x3000] = 0x08;
        b[0x3001] = 0x10;
        b[0x3002] = 13;
        b[0x3003] = 0x00;
        for i in 0..13u32 {
            b[(0x3004 + i * 2) as usize] = (i & 0xff) as u8;
            b[(0x3004 + i * 2 + 1) as usize] = 0x00;
        }
        b[0x301e] = 0xcc;
        b[0x301f] = 0x00;
        b[0x3020..0x3024].copy_from_slice(&0x2000u32.to_le_bytes());
        let r = decode_unwind(&b);
        assert!(r.is_complete(), "{}", r.blockers.join("; "));
        assert_eq!(r.unwind_infos[0].handler_rva, Some(0x2000));
        assert_eq!(r.unwind_infos[0].status, UnwindInfoStatus::Valid);
    }

    #[test]
    fn h4d_final_even_count_of_codes_handler_no_padding() {
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        b[0x3000] = 0x08;
        b[0x3001] = 0x10;
        b[0x3002] = 4;
        b[0x3003] = 0x00;
        for i in 0..4u32 {
            b[(0x3004 + i * 2) as usize] = (i & 0xff) as u8;
            b[(0x3004 + i * 2 + 1) as usize] = 0x00;
        }
        b[0x300c..0x3010].copy_from_slice(&0x2000u32.to_le_bytes());
        let r = decode_unwind(&b);
        assert!(r.is_complete(), "{}", r.blockers.join("; "));
        assert_eq!(r.unwind_infos[0].handler_rva, Some(0x2000));
        assert_eq!(r.unwind_infos[0].status, UnwindInfoStatus::Valid);
    }

    #[test]
    fn h4d_final_chaininfo_with_handler_is_invalid_flags() {
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        b[0x3000] = 0x29;
        b[0x3001] = 0x10;
        b[0x3002] = 0;
        b[0x3003] = 0;
        let r = decode_unwind(&b);
        assert!(!r.is_complete());
        assert!(r
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::InvalidFlags));
    }

    // GTO-H4-D-P5: final decoder UNWIND_CODE field order must match the
    // runtime observer: byte[0]=CodeOffset, byte[1] low nibble=UnwindOp,
    // byte[1] high nibble=OpInfo.
    #[test]
    fn p5_final_unwind_code_field_order() {
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        b[0x3000] = 0x00;
        b[0x3001] = 0x10;
        b[0x3002] = 1;
        b[0x3003] = 0x00;
        b[0x3004] = 0x05; // CodeOffset = byte[0]
        b[0x3005] = 0x42; // UnwindOp = 2 (low nibble), OpInfo = 4 (high nibble)
        let r = decode_unwind(&b);
        assert!(r.is_complete(), "{}", r.blockers.join("; "));
        let c = &r.unwind_infos[0].codes[0];
        assert_eq!(c.code_offset, 0x05, "CodeOffset = byte[0]");
        assert_eq!(c.unwind_op, 0x02, "UnwindOp = byte[1] low nibble");
        assert_eq!(c.op_info, 0x04, "OpInfo = byte[1] high nibble");
    }

    // GTO-H4-D-P5: final decoder parses CHAININFO as a full 12-byte tuple.
    #[test]
    fn p5_final_chaininfo_full_12_byte_tuple() {
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        b[0x3000] = 0x04 << 3; // flags=CHAININFO
        b[0x3001] = 0x10;
        b[0x3002] = 0;
        b[0x3003] = 0;
        b[0x3004..0x3008].copy_from_slice(&0x1000u32.to_le_bytes()); // Begin
        b[0x3008..0x300c].copy_from_slice(&0x1100u32.to_le_bytes()); // End
        b[0x300c..0x3010].copy_from_slice(&0x3000u32.to_le_bytes()); // UnwindInfoAddress
        let r = decode_unwind(&b);
        assert!(r.is_complete(), "{}", r.blockers.join("; "));
        let u = &r.unwind_infos[0];
        assert_eq!(u.status, UnwindInfoStatus::Valid);
        let c = u.chain.as_ref().expect("chain parsed");
        assert_eq!(c.status, ChainInfoStatus::Valid);
        assert_eq!(c.begin_address, 0x1000);
        assert_eq!(c.end_address, 0x1100);
        assert_eq!(c.unwind_info_address, 0x3000);
        assert_eq!(u.handler_rva, None, "chain must not populate handler_rva");
    }

    // GTO-H4-D-P5: CHAININFO 12-byte tail truncated (crosses SizeOfImage)
    // is fail-closed via the full-span bound check.
    #[test]
    fn p5_final_chaininfo_tail_truncated_fails_closed() {
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3ff4, 0x1000, 0x4000);
        // unwind at 0x3ff4: header + 12B chain crosses SizeOfImage 0x4000.
        b[0x3ff4] = 0x04 << 3;
        b[0x3ff5] = 0x10;
        b[0x3ff6] = 0;
        b[0x3ff7] = 0;
        b[0x3ff8..0x3ffc].copy_from_slice(&0x1000u32.to_le_bytes());
        b[0x3ffc..0x4000].copy_from_slice(&0x1100u32.to_le_bytes());
        // UnwindInfoAddress would land beyond 0x4000 — 8 bytes only.
        let r = decode_unwind(&b);
        assert!(!r.is_complete(), "truncated chain tail must fail closed");
        assert!(r
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::CodesOutOfBounds));
    }

    // GTO-H4-D-P5: CHAININFO Begin >= End is fail-closed.
    #[test]
    fn p5_final_chaininfo_begin_not_less_end_fails_closed() {
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        b[0x3000] = 0x04 << 3;
        b[0x3001] = 0x10;
        b[0x3002] = 0;
        b[0x3003] = 0;
        b[0x3004..0x3008].copy_from_slice(&0x1100u32.to_le_bytes()); // Begin >= End
        b[0x3008..0x300c].copy_from_slice(&0x1100u32.to_le_bytes());
        b[0x300c..0x3010].copy_from_slice(&0x3000u32.to_le_bytes());
        let r = decode_unwind(&b);
        assert!(!r.is_complete(), "Begin>=End chain must fail closed");
        assert!(r
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::InvalidChain));
    }

    // GTO-H4-D-P5: CHAININFO RVA out of image is fail-closed.
    #[test]
    fn p5_final_chaininfo_rva_out_of_image_fails_closed() {
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        b[0x3000] = 0x04 << 3;
        b[0x3001] = 0x10;
        b[0x3002] = 0;
        b[0x3003] = 0;
        b[0x3004..0x3008].copy_from_slice(&0x1000u32.to_le_bytes());
        b[0x3008..0x300c].copy_from_slice(&0x1100u32.to_le_bytes());
        b[0x300c..0x3010].copy_from_slice(&0x8000u32.to_le_bytes()); // out of image
        let r = decode_unwind(&b);
        assert!(!r.is_complete(), "out-of-image chain must fail closed");
        assert!(r
            .unwind_infos
            .iter()
            .any(|u| u.status == UnwindInfoStatus::InvalidChain));
    }

    // GTO-H4-D-P5: EHANDLER 4-byte tail truncated is fail-closed.
    #[test]
    fn p5_final_eh_handler_tail_truncated_fails_closed() {
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3ffc, 0x1000, 0x4000);
        b[0x3ffc] = 0x01 << 3; // flags=EHANDLER
        b[0x3ffd] = 0x10;
        b[0x3ffe] = 0x00;
        b[0x3fff] = 0x00;
        // handler slot @0x4000..0x4004 crosses SizeOfImage 0x4000.
        let r = decode_unwind(&b);
        assert!(!r.is_complete(), "truncated EH handler must fail closed");
    }

    // GTO-H4-D-P5: runtime observer and final decoder agree field-for-field
    // on a CHAININFO layout (12-byte chain tuple, code field order).
    #[test]
    fn p5_runtime_final_chaininfo_parity() {
        use crate::exception_observation::observe_exception_runtime;
        // Build the candidate bytes with a CHAININFO unwind.
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        b[0x3000] = 0x04 << 3; // flags=CHAININFO
        b[0x3001] = 0x10;
        b[0x3002] = 1; // 1 code
        b[0x3003] = 0x00;
        b[0x3004] = 0x07; // CodeOffset = 0x07 (byte[0])
        b[0x3005] = 0x63; // UnwindOp=3, OpInfo=6 (byte[1])
        b[0x3006..0x3008].copy_from_slice(&[0x00, 0x00]); // padding (odd count)
        b[0x3008..0x300c].copy_from_slice(&0x1000u32.to_le_bytes()); // chain Begin
        b[0x300c..0x3010].copy_from_slice(&0x1100u32.to_le_bytes()); // chain End
        b[0x3010..0x3014].copy_from_slice(&0x3000u32.to_le_bytes()); // chain UnwindInfoAddress
        let final_report = ExceptionFinalDecoder::from_candidate_bytes(&b)
            .expect("candidate parses")
            .decode();
        assert!(
            final_report.is_complete(),
            "{}",
            final_report.blockers.join("; ")
        );

        // Runtime observer on the same memory image.
        let pe = PeHeader::from_bytes(&b).expect("PE parses");
        let runtime = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader_of(&b, 0x140000000),
        );
        assert!(runtime.is_complete(), "{}", runtime.failure_summary());
        assert_eq!(
            runtime.unwind_infos, final_report.unwind_infos,
            "UNWIND_INFO field-for-field parity (incl. chain)"
        );
        let cmp = compare_runtime_final(&runtime, &final_report);
        assert!(cmp.all_preserved, "{}", cmp.blockers.join("; "));
    }

    // GTO-H4-D-P5: code-field order regression — a byte[0]=0x05, byte[1]=0x42
    // slot must decode identically in both parsers.
    #[test]
    fn p5_runtime_final_code_field_order_parity() {
        use crate::exception_observation::observe_exception_runtime;
        let mut b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        b[0x3000] = 0x00;
        b[0x3001] = 0x10;
        b[0x3002] = 1;
        b[0x3003] = 0x00;
        b[0x3004] = 0x05;
        b[0x3005] = 0x42;
        let final_report = ExceptionFinalDecoder::from_candidate_bytes(&b)
            .expect("parses")
            .decode();
        let pe = PeHeader::from_bytes(&b).expect("PE parses");
        let runtime = observe_exception_runtime(
            &pe,
            0x140000000,
            0x140000000,
            memory_reader_of(&b, 0x140000000),
        );
        assert_eq!(runtime.unwind_infos, final_report.unwind_infos);
        assert_eq!(
            runtime.unwind_infos[0].codes,
            final_report.unwind_infos[0].codes
        );
        let c = &final_report.unwind_infos[0].codes[0];
        assert_eq!((c.code_offset, c.unwind_op, c.op_info), (0x05, 0x02, 0x04));
    }

    fn memory_reader_of(
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

    #[test]
    fn h4d_final_runtime_function_12_byte_tuple() {
        let b = pe_with_pdata(0x2000, 12, 0x1000, 0x1100, 0x3000, 0x1000, 0x4000);
        let r = decode_unwind(&b);
        assert!(r.is_complete(), "{}", r.blockers.join("; "));
        assert_eq!(r.function_count, 1);
        assert_eq!(r.functions[0].begin_rva, 0x1000);
        assert_eq!(r.functions[0].end_rva, 0x1100);
        assert_eq!(r.functions[0].unwind_info_rva, 0x3000);
        assert_eq!(r.functions[0].status, RuntimeFunctionStatus::Valid);
    }
}
