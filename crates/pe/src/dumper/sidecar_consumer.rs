//! T0.11 sidecar consumer — consume a dumped session's module table to clean
//! an older PE artifact that still embeds absolute pointers frozen to a
//! *previous* ASLR session.
//!
//! T0.7 archives the *dumped* session's system-DLL ASLR table
//! (`<output>.session_modules.json`, `persist_session_modules_sidecar`) but
//! ships no consumer. An older artifact written by a previous boot session
//! embeds absolute module pointers of that session; after the next reboot the
//! system DLLs are re-based by ASLR, so those pointers land on unmapped
//! memory and AV at startup. Concrete evidence (T0.5): the xx11 host
//! `rev2_unpacked.exe` (sha256 `36043cb4…`) embeds old-ntdll `0x7ffeeb426390`
//! at RVA `0x112c10`; after the 07:58 reboot ntdll moved to `0x7ffa952a0000`,
//! the fixed pointer had no mapping and the host AV'd (`c0000005`) before
//! core.dll could load. This module is that missing consumer:
//!
//! * scan the artifact's writable data sections for 8-byte-aligned QWORDs in
//!   the high-ASLR module band;
//! * a value landing inside an **old-session** module range is a stale
//!   session pointer → relocate it onto the **current** session's layout by
//!   module name + intra-module offset (`old_base + off → new_base + off`);
//! * when the old module cannot be mapped (unnamed entry, or the name is
//!   absent from the current table) → zero the pointer so load-time
//!   resolution rebinds (same contract as
//!   `data_reinit::is_stale_absolute_pointer`);
//! * image-own addresses (`image_base..image_end`) and everything below the
//!   high-ASLR band keep the T0.7 behaviour — untouched (runtime rebase owns
//!   image VAs; low-band heap scrubbing is the dump pipeline's job and the
//!   artifact already passed it when it was produced).
//!
//! PE structure (DOS/NT headers, section table, import / relocation
//! directories, .text) is never rewritten — only writable data-section QWORD
//! payloads change, so the artifact stays a structurally valid PE.

use std::fmt;
use std::path::Path;

use crate::header::PeHeader;

use super::data_reinit::{is_data_like_section_name, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};

/// High-ASLR x64 module / system image band floor (same constant as
/// `data_reinit`). Pointers in this band are session module pointers, not
/// process-local heap garbage.
pub const HIGH_ASLR_MODULE_MIN: u64 = 0x0000_7ff0_0000_0000;

/// A single entry of a session module table: module image name (empty when
/// the base was observed without a name — range-match only, never
/// relocatable) plus `[base, end)` (end-exclusive) of its ASLR mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTableEntry {
    pub name: String,
    pub base: u64,
    pub end: u64,
}

/// Outcome counters of one cleanup pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct CleanupStats {
    /// Stale old-session pointers relocated onto the current session's
    /// module base + same intra-module offset.
    pub relocated: usize,
    /// Stale old-session pointers zeroed because the owning module could not
    /// be mapped (unnamed old entry, or name missing from the current table).
    pub cleared: usize,
    /// QWORDs inside the artifact's own `image_base..image_end` (preserved,
    /// runtime rebase owns image VAs).
    pub preserved_image: usize,
    /// High-ASLR QWORDs not owned by any old-session module (preserved).
    pub untouched_high: usize,
    /// Aligned QWORDs below the high-ASLR band (preserved; low-band
    /// scrubbing is the dump pipeline's responsibility).
    pub untouched_low: usize,
}

/// Sidecar parse/validation failure.
#[derive(Debug)]
pub enum SidecarError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Schema(String),
}

impl fmt::Display for SidecarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SidecarError::Io(e) => write!(f, "session table I/O error: {e}"),
            SidecarError::Json(e) => write!(f, "session table JSON error: {e}"),
            SidecarError::Schema(s) => write!(f, "session table schema error: {s}"),
        }
    }
}

impl std::error::Error for SidecarError {}

impl From<std::io::Error> for SidecarError {
    fn from(e: std::io::Error) -> Self {
        SidecarError::Io(e)
    }
}

impl From<serde_json::Error> for SidecarError {
    fn from(e: serde_json::Error) -> Self {
        SidecarError::Json(e)
    }
}

/// Load and parse a session module table sidecar (`mida.session-modules/v1`).
pub fn load_session_table(path: &Path) -> Result<Vec<SessionTableEntry>, SidecarError> {
    let text = std::fs::read_to_string(path)?;
    parse_session_table(&text)
}

/// Parse a `mida.session-modules/v1` sidecar text. Module names may be empty
/// for entries reconstructed from bare observed bases (range-match only).
pub fn parse_session_table(text: &str) -> Result<Vec<SessionTableEntry>, SidecarError> {
    #[derive(serde::Deserialize)]
    struct RawSidecar {
        schema_version: String,
        #[allow(dead_code)]
        candidate_sha256: Option<String>,
        modules: Vec<RawModule>,
    }
    #[derive(serde::Deserialize)]
    struct RawModule {
        name: String,
        base: String,
        end: String,
    }

    let raw: RawSidecar = serde_json::from_str(text)?;
    if raw.schema_version != "mida.session-modules/v1" {
        return Err(SidecarError::Schema(format!(
            "unexpected schema '{}' (expected 'mida.session-modules/v1')",
            raw.schema_version
        )));
    }
    let mut out = Vec::with_capacity(raw.modules.len());
    for m in raw.modules {
        let base = parse_hex_u64(&m.base)?;
        let end = parse_hex_u64(&m.end)?;
        if base >= end {
            return Err(SidecarError::Schema(format!(
                "module '{}' range [base={base:#x}, end={end:#x}) is empty or inverted",
                m.name
            )));
        }
        out.push(SessionTableEntry {
            name: m.name,
            base,
            end,
        });
    }
    Ok(out)
}

/// Serialize a session table to `mida.session-modules/v1` JSON text
/// (helper mode: emit an old-session table reconstructed from a crash site).
pub fn serialize_session_table(
    entries: &[SessionTableEntry],
    candidate_sha256: Option<&str>,
) -> Result<String, serde_json::Error> {
    #[derive(serde::Serialize)]
    struct RawModule<'a> {
        name: &'a str,
        base: String,
        end: String,
    }
    #[derive(serde::Serialize)]
    struct RawSidecar<'a> {
        schema_version: &'a str,
        candidate_sha256: Option<&'a str>,
        modules: Vec<RawModule<'a>>,
    }
    let modules = entries
        .iter()
        .map(|e| RawModule {
            name: &e.name,
            base: format!("{:#x}", e.base),
            end: format!("{:#x}", e.end),
        })
        .collect();
    let raw = RawSidecar {
        schema_version: "mida.session-modules/v1",
        candidate_sha256,
        modules,
    };
    serde_json::to_string_pretty(&raw)
}

fn parse_hex_u64(s: &str) -> Result<u64, SidecarError> {
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(body, 16)
        .map_err(|e| SidecarError::Schema(format!("cannot parse base/end '{}' as hex: {e}", s)))
}

/// Rewrite an old-session-bound PE artifact against the current session's
/// module table. `buf` must hold the full artifact bytes (headers + sections,
/// file layout as parsed by `pe`). Returns the cleanup counters.
pub fn cleanup_artifact(
    pe: &PeHeader,
    buf: &mut [u8],
    old_table: &[SessionTableEntry],
    new_table: &[SessionTableEntry],
) -> CleanupStats {
    let image_base = pe.nt_headers.optional_header.image_base;
    let image_end = image_base.saturating_add(pe.size_of_image() as u64);
    let mut stats = CleanupStats::default();
    for section in pe.sections.iter().filter(|s| {
        s.characteristics & IMAGE_SCN_MEM_WRITE != 0
            && s.characteristics & IMAGE_SCN_MEM_EXECUTE == 0
            && is_data_like_section_name(&s.name)
    }) {
        let start = section.virtual_address as usize;
        let end = start
            .saturating_add(section.virtual_size as usize)
            .min(buf.len());
        rewrite_section_pointers(
            buf, start, end, image_base, image_end, old_table, new_table, &mut stats,
        );
    }
    stats
}

/// Rewrite 8-byte-aligned QWORDs in `buf[start..end]` (a writable data
/// section) that reference old-session module ranges. Exposed separately so
/// unit tests can drive it without a full PE.
pub(crate) fn rewrite_section_pointers(
    buf: &mut [u8],
    start: usize,
    end: usize,
    image_base: u64,
    image_end: u64,
    old_table: &[SessionTableEntry],
    new_table: &[SessionTableEntry],
    stats: &mut CleanupStats,
) {
    if end.saturating_sub(start) < 8 {
        return;
    }
    let aligned_start = (start + 7) & !7;
    for off in (aligned_start..end.saturating_sub(7)).step_by(8) {
        let value = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or_default());
        if (image_base..image_end).contains(&value) {
            stats.preserved_image += 1;
            continue;
        }
        if value < HIGH_ASLR_MODULE_MIN {
            stats.untouched_low += 1;
            continue;
        }
        let Some(old) = old_table.iter().find(|e| e.base <= value && value < e.end) else {
            stats.untouched_high += 1;
            continue;
        };
        if !old.name.is_empty() {
            if let Some(nv) = relocate_to_current(old, value, new_table) {
                buf[off..off + 8].copy_from_slice(&nv.to_le_bytes());
                stats.relocated += 1;
                continue;
            }
        }
        // Unnamed old entry or unmappable name → cannot relocate reliably;
        // zero so load-time resolution rebinds instead of AV-ing on the
        // stale unmapped address.
        buf[off..off + 8].fill(0);
        stats.cleared += 1;
    }
}

/// `old_base + (value - old_base) → new_base + (value - old_base)` by module
/// name. `None` when the name is absent from the current table or the
/// relocated value would fall outside the target module range.
fn relocate_to_current(
    old: &SessionTableEntry,
    value: u64,
    new_table: &[SessionTableEntry],
) -> Option<u64> {
    let new = new_table
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(&old.name))?;
    let off = value.checked_sub(old.base)?;
    let nv = new.base.checked_add(off)?;
    (nv < new.end).then_some(nv)
}

/// Helper mode: build an old-session table from known named module ranges
/// plus a set of bare observed addresses (e.g. a crash site's pointer set).
/// Addresses already covered by a known range are not duplicated; uncovered
/// ones become unnamed range-match-only entries so the consumer can at least
/// recognize (and zero) them.
pub fn build_old_table(
    known: Vec<SessionTableEntry>,
    old_addresses: &[u64],
) -> Vec<SessionTableEntry> {
    let mut out = known;
    for &addr in old_addresses {
        if out.iter().any(|e| e.base <= addr && addr < e.end) {
            continue;
        }
        out.push(SessionTableEntry {
            name: String::new(),
            base: addr,
            end: addr.saturating_add(1),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, base: u64, end: u64) -> SessionTableEntry {
        SessionTableEntry {
            name: name.to_string(),
            base,
            end,
        }
    }

    const OLD_NTDLL: u64 = 0x7ffe_eb32_0000;
    const OLD_NTDLL_END: u64 = OLD_NTDLL + 0x26_6000;
    const NEW_NTDLL: u64 = 0x7ffa_952a_0000;
    const NEW_NTDLL_END: u64 = NEW_NTDLL + 0x26_6000;
    // T0.5 evidence: old ntdll base + 0x106390.
    const STALE_CRASH_PTR: u64 = OLD_NTDLL + 0x10_6390;

    fn old_table() -> Vec<SessionTableEntry> {
        vec![
            entry("ntdll.dll", OLD_NTDLL, OLD_NTDLL_END),
            entry("", 0x7ffe_e950_0000, 0x7ffe_e950_0000 + 0x1_0000), // unnamed
        ]
    }

    fn new_table() -> Vec<SessionTableEntry> {
        vec![entry("ntdll.dll", NEW_NTDLL, NEW_NTDLL_END)]
    }

    #[test]
    fn parses_session_table_json() {
        let text = r#"{
            "schema_version": "mida.session-modules/v1",
            "candidate_sha256": "fc98c187124eb4257813a6b953a1f508b5daa6e5fcd4d93a52483c540ba1cb9b",
            "modules": [
                {"name": "ntdll.dll", "base": "0x7ffa952a0000", "end": "0x7ffa95506000"},
                {"name": "", "base": "0x7ffeeb586000", "end": "0x7ffeeb6a0000"}
            ]
        }"#;
        let table = parse_session_table(text).expect("valid sidecar parses");
        assert_eq!(table.len(), 2);
        assert_eq!(table[0].name, "ntdll.dll");
        assert_eq!(table[0].base, NEW_NTDLL);
        assert_eq!(table[0].end, NEW_NTDLL_END);
        assert_eq!(table[1].name, "");
        assert_eq!(table[1].base, 0x7ffe_eb58_6000);
    }

    #[test]
    fn rejects_wrong_schema_and_bad_hex() {
        let wrong_schema = r#"{"schema_version": "other/v2", "modules": []}"#;
        assert!(matches!(
            parse_session_table(wrong_schema),
            Err(SidecarError::Schema(_))
        ));
        let bad_hex = r#"{"schema_version": "mida.session-modules/v1", "modules": [{"name":"x","base":"zzz","end":"0x10"}]}"#;
        assert!(matches!(
            parse_session_table(bad_hex),
            Err(SidecarError::Schema(_))
        ));
        let inverted = r#"{"schema_version": "mida.session-modules/v1", "modules": [{"name":"x","base":"0x20","end":"0x10"}]}"#;
        assert!(matches!(
            parse_session_table(inverted),
            Err(SidecarError::Schema(_))
        ));
    }

    #[test]
    fn relocates_named_old_module_pointer_to_current_base() {
        let mut data = vec![0u8; 40]; // exactly 5 aligned QWORD slots
                                      // Slot 0: stale old-ntdll crash pointer (T0.5 RVA 0x112c10 value).
        data[0..8].copy_from_slice(&STALE_CRASH_PTR.to_le_bytes());
        // Slot 8: inside the unnamed old range → must be zeroed.
        let unnamed = 0x7ffe_e950_0000u64 + 0x1234;
        data[8..16].copy_from_slice(&unnamed.to_le_bytes());
        // Slot 16: image-own VA → preserved.
        let image_va = 0x1400_0000u64 + 0x1234;
        data[16..24].copy_from_slice(&image_va.to_le_bytes());
        // Slot 24: high ASLR but not in old table → preserved.
        let other_high = 0x7ff9_0000_0000u64 + 0x5678;
        data[24..32].copy_from_slice(&other_high.to_le_bytes());
        // Slot 32: low-band heap pointer → preserved (pipeline's job).
        let low_heap = 0x8d3e40u64;
        data[32..40].copy_from_slice(&low_heap.to_le_bytes());

        let old = old_table();
        let new = new_table();
        let mut stats = CleanupStats::default();
        let len = data.len();
        rewrite_section_pointers(
            &mut data,
            0,
            len,
            0x1400_0000,
            0x1400_0000 + 0x2000,
            &old,
            &new,
            &mut stats,
        );

        // Relocated: new ntdll + same offset 0x106390.
        let expected = NEW_NTDLL + 0x10_6390;
        assert_eq!(
            u64::from_le_bytes(data[0..8].try_into().unwrap_or_default()),
            expected,
            "named old module pointer must relocate to current base + offset"
        );
        // Unnamed old entry → zeroed.
        assert_eq!(
            u64::from_le_bytes(data[8..16].try_into().unwrap_or_default()),
            0
        );
        // Image-own / unmatched high / low band all preserved.
        assert_eq!(
            u64::from_le_bytes(data[16..24].try_into().unwrap_or_default()),
            image_va
        );
        assert_eq!(
            u64::from_le_bytes(data[24..32].try_into().unwrap_or_default()),
            other_high
        );
        assert_eq!(
            u64::from_le_bytes(data[32..40].try_into().unwrap_or_default()),
            low_heap
        );

        assert_eq!(stats.relocated, 1);
        assert_eq!(stats.cleared, 1);
        assert_eq!(stats.preserved_image, 1);
        assert_eq!(stats.untouched_high, 1);
        assert_eq!(stats.untouched_low, 1);
    }

    #[test]
    fn unmappable_name_zeroes_instead_of_relocating() {
        // Old entry has a name, but the current table does not contain it →
        // cannot relocate; contract: zero.
        let old = vec![entry("ole32.dll", 0x7ffe_e000_0000, 0x7ffe_e000_4000)];
        let new = vec![entry("ntdll.dll", NEW_NTDLL, NEW_NTDLL_END)];
        let ptr = 0x7ffe_e000_1000u64;
        let mut data = vec![0u8; 0x10];
        data[0..8].copy_from_slice(&ptr.to_le_bytes());
        let mut stats = CleanupStats::default();
        let len = data.len();
        rewrite_section_pointers(
            &mut data,
            0,
            len,
            0x1400_0000,
            0x1400_0000 + 0x2000,
            &old,
            &new,
            &mut stats,
        );
        assert_eq!(stats.relocated, 0);
        assert_eq!(stats.cleared, 1);
        assert_eq!(
            u64::from_le_bytes(data[0..8].try_into().unwrap_or_default()),
            0
        );
    }

    #[test]
    fn relocated_value_must_stay_inside_target_module() {
        // Old offset beyond the new module's size → refuse relocate, zero.
        let old = vec![entry("ntdll.dll", OLD_NTDLL, OLD_NTDLL_END)];
        let new = vec![entry("ntdll.dll", NEW_NTDLL, NEW_NTDLL + 0x1000)]; // tiny target
        let ptr = OLD_NTDLL + 0x10_6390; // offset far beyond the 0x1000 target
        let mut data = vec![0u8; 0x10];
        data[0..8].copy_from_slice(&ptr.to_le_bytes());
        let mut stats = CleanupStats::default();
        let len = data.len();
        rewrite_section_pointers(
            &mut data,
            0,
            len,
            0x1400_0000,
            0x1400_0000 + 0x2000,
            &old,
            &new,
            &mut stats,
        );
        assert_eq!(stats.relocated, 0);
        assert_eq!(stats.cleared, 1);
    }

    #[test]
    fn build_old_table_dedups_known_and_adds_unnamed() {
        let known = vec![entry("ntdll.dll", OLD_NTDLL, OLD_NTDLL_END)];
        let addresses = [
            STALE_CRASH_PTR,            // covered by known ntdll → not duplicated
            0x7ffe_e950_0000u64 + 0x50, // uncovered → unnamed entry
        ];
        let table = build_old_table(known, &addresses);
        assert_eq!(table.len(), 2);
        assert_eq!(table[0].name, "ntdll.dll");
        assert_eq!(table[1].name, "");
        assert_eq!(table[1].base, 0x7ffe_e950_0000u64 + 0x50);
    }

    #[test]
    fn serialize_round_trip_preserves_entries() {
        let table = old_table();
        let text = serialize_session_table(&table, Some("deadbeef")).expect("serializes");
        let parsed = parse_session_table(&text).expect("round-trip parses");
        assert_eq!(parsed, table);
    }

    #[test]
    fn pe_structure_bytes_untouched_by_cleanup() {
        // A cleanup pass must never touch headers/section table/import data —
        // only writable data-section QWORD payloads. Build a minimal PE64
        // whose single .text section is executable → cleanup must rewrite
        // nothing and preserve every byte.
        let mut buf = crate::header::make_minimal_pe64();
        let original = buf.clone();
        let pe = PeHeader::from_bytes(&buf).expect("minimal PE parses");
        let old = old_table();
        let new = new_table();
        let stats = cleanup_artifact(&pe, &mut buf, &old, &new);
        assert_eq!(stats.relocated, 0);
        assert_eq!(stats.cleared, 0);
        assert_eq!(buf, original, "cleanup must not touch non-data bytes");
    }

    // -----------------------------------------------------------------------
    // T0.7 end-to-end offline closure: build a synthetic PE with a writable
    // .data section, drive the full serialize → cleanup_artifact chain against
    // two ASLR-differing session tables, and assert the artifact no longer
    // embeds any pointer inside an old-session module range.
    // -----------------------------------------------------------------------

    const OLD_KERNEL32: u64 = 0x7ffe_e000_0000;
    const OLD_KERNEL32_END: u64 = OLD_KERNEL32 + 0x40_0000;
    const NEW_KERNEL32: u64 = 0x7ffa_9100_0000;
    const NEW_KERNEL32_END: u64 = NEW_KERNEL32 + 0x40_0000;

    /// Minimal PE32+ with two sections (.text executable at file offset
    /// 0x200, .data writable at file offset 0x400). Each section's
    /// VirtualAddress is set equal to its PointerToRawData so cleanup's
    /// `buf[section.virtual_address..+virtual_size]` slice lands on the raw
    /// bytes (real dumps keep RVA == raw offset for data sections). Headers
    /// occupy 0x200 bytes; .text raw data sits at file offset 0x200 (0x200
    /// bytes); .data raw data sits at file offset 0x400 (0x1000 bytes).
    /// Returns the full file image.
    fn synthetic_pe_with_data() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400 + 0x1000]; // headers + .text raw + .data raw
        buf[0] = 0x4D; // 'M'
        buf[1] = 0x5A; // 'Z'
        buf[60..64].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
        let nt = 0x40usize;
        buf[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let fh = nt + 4;
        buf[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // machine AMD64
        buf[fh + 2..fh + 4].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
        buf[fh + 16..fh + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        buf[fh + 18..fh + 20].copy_from_slice(&0x22u16.to_le_bytes()); // Characteristics
        let oh = nt + 24;
        buf[oh..oh + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
        buf[oh + 16..oh + 18].copy_from_slice(&0x1000u16.to_le_bytes()); // AddressOfEntryPoint
        buf[oh + 24..oh + 32].copy_from_slice(&0x140_0000_00u64.to_le_bytes()); // ImageBase
        buf[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        buf[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        buf[oh + 56..oh + 60].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage
        buf[oh + 60..oh + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        buf[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
                                                                       // Section 1: .text — VA == raw offset 0x200.
        let s1 = nt + 24 + 240;
        buf[s1..s1 + 8].copy_from_slice(b".text\0\0\0");
        buf[s1 + 8..s1 + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        buf[s1 + 12..s1 + 16].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualAddress
        buf[s1 + 16..s1 + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        buf[s1 + 20..s1 + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        buf[s1 + 36..s1 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // READ|EXEC|CODE
                                                                              // Section 2: .data — VA == raw offset 0x400.
        let s2 = s1 + 40;
        buf[s2..s2 + 8].copy_from_slice(b".data\0\0\0");
        buf[s2 + 8..s2 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        buf[s2 + 12..s2 + 16].copy_from_slice(&0x400u32.to_le_bytes()); // VirtualAddress
        buf[s2 + 16..s2 + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // SizeOfRawData
        buf[s2 + 20..s2 + 24].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        buf[s2 + 36..s2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes()); // READ|WRITE|INIT
        buf
    }

    /// Old-session table matching the synthetic PE's embedded pointers: ntdll
    /// and kernel32 at their old ASLR bases, plus an unnamed high-ASLR range.
    fn e2e_old_table() -> Vec<SessionTableEntry> {
        vec![
            entry("ntdll.dll", OLD_NTDLL, OLD_NTDLL_END),
            entry("kernel32.dll", OLD_KERNEL32, OLD_KERNEL32_END),
            entry("", 0x7ffe_e950_0000, 0x7ffe_e950_0000 + 0x1_0000),
        ]
    }

    /// Current-session table: same module names at new ASLR bases.
    fn e2e_new_table() -> Vec<SessionTableEntry> {
        vec![
            entry("ntdll.dll", NEW_NTDLL, NEW_NTDLL_END),
            entry("kernel32.dll", NEW_KERNEL32, NEW_KERNEL32_END),
        ]
    }

    #[test]
    fn e2e_cleanup_relocates_old_session_pointers_and_leaves_none_behind() {
        // Build the synthetic artifact with 4 embedded absolute pointers in
        // .data (file offset 0x400):
        //   +0x00 old-ntdll  ptr (named → relocate)
        //   +0x08 old-kernel32 ptr (named → relocate)
        //   +0x10 unnamed old range ptr (→ zero)
        //   +0x18 old-ntdll offset that overflows new module end (→ zero)
        let mut artifact = synthetic_pe_with_data();
        let data_off = 0x400usize;
        let stale_ntdll = OLD_NTDLL + 0x10_6390;
        let stale_kernel32 = OLD_KERNEL32 + 0x1234;
        let unnamed_ptr: u64 = 0x7ffe_e950_0000 + 0x2000;
        let too_far_kernel32: u64 = OLD_KERNEL32 + 0x20_0000; // inside old kernel32 range
        artifact[data_off..data_off + 8].copy_from_slice(&stale_ntdll.to_le_bytes());
        artifact[data_off + 8..data_off + 16].copy_from_slice(&stale_kernel32.to_le_bytes());
        artifact[data_off + 16..data_off + 24].copy_from_slice(&unnamed_ptr.to_le_bytes());
        artifact[data_off + 24..data_off + 32].copy_from_slice(&too_far_kernel32.to_le_bytes());

        // Serialize both tables with the exact writer schema (same JSON
        // contract persist_session_modules_sidecar uses), then parse them back
        // through the consumer's reader. The new kernel32 is SMALLER than the
        // old one so an intra-old-range offset can fall outside the new range
        // and must be zeroed (relocate_to_current refuses out-of-range targets).
        let mut new_table = e2e_new_table();
        let small_kernel32_end = NEW_KERNEL32 + 0x10_0000;
        for e in new_table.iter_mut() {
            if e.name == "kernel32.dll" {
                e.end = small_kernel32_end;
            }
        }
        let old_text = serialize_session_table(&e2e_old_table(), Some("deadbeef"))
            .expect("old table serializes");
        let new_text =
            serialize_session_table(&new_table, Some("cafebabe")).expect("new table serializes");
        let old = parse_session_table(&old_text).expect("old table parses");
        let new = parse_session_table(&new_text).expect("new table parses");

        let pe = PeHeader::from_bytes(&artifact).expect("synthetic PE parses");
        let stats = cleanup_artifact(&pe, &mut artifact, &old, &new);

        // Named modules relocated to current base + same intra-module offset.
        let relocated_ntdll = NEW_NTDLL + 0x10_6390;
        let relocated_kernel32 = NEW_KERNEL32 + 0x1234;
        assert_eq!(read_qword(&artifact, data_off), relocated_ntdll);
        assert_eq!(read_qword(&artifact, data_off + 8), relocated_kernel32);
        // Unnamed and unmappable → zeroed.
        assert_eq!(read_qword(&artifact, data_off + 16), 0);
        assert_eq!(read_qword(&artifact, data_off + 24), 0);

        // Counters match actual rewrites.
        assert_eq!(stats.relocated, 2);
        assert_eq!(stats.cleared, 2);
        assert_eq!(stats.preserved_image, 0);
        assert_eq!(stats.untouched_high, 0);
        // .data has 0x1000 bytes = 512 QWORDs; 4 carry our planted pointers,
        // the remaining 508 are zero (low band) → preserved as untouched_low.
        assert_eq!(stats.untouched_low, 508);

        // Static self-check: no absolute pointer in the artifact falls inside
        // any old-session module range anymore.
        let data_end = data_off + 0x1000;
        let mut off = data_off;
        while off + 8 <= data_end {
            let v = read_qword(&artifact, off);
            if v >= HIGH_ASLR_MODULE_MIN {
                for e in &old {
                    assert!(
                        !(e.base <= v && v < e.end),
                        "stale old-session pointer {v:#x} survives at file offset {off:#x}"
                    );
                }
            }
            off += 8;
        }
    }

    #[test]
    fn e2e_cleanup_scan_only_reports_without_rewrite() {
        // With an empty old table (no stale session known), cleanup must not
        // touch the artifact: the high-ASLR pointers survive for rebase and
        // every counter stays zero (mirrors data_reinit's no-table contract).
        let mut artifact = synthetic_pe_with_data();
        let data_off = 0x400usize;
        let stale_ntdll = OLD_NTDLL + 0x10_6390;
        artifact[data_off..data_off + 8].copy_from_slice(&stale_ntdll.to_le_bytes());
        let original = artifact.clone();

        let pe = PeHeader::from_bytes(&artifact).expect("synthetic PE parses");
        let stats = cleanup_artifact(&pe, &mut artifact, &[], &e2e_new_table());
        assert_eq!(stats.relocated, 0);
        assert_eq!(stats.cleared, 0);
        assert_eq!(stats.untouched_high, 1);
        assert_eq!(artifact, original, "no-table scan must be a no-op");
    }

    fn read_qword(buf: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or_default())
    }
}
