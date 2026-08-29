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
}
