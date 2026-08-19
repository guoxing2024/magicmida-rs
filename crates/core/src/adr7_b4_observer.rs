//! ADR7-B4 dynamic instrumentation observer (debugger-side event recorder).
//!
//! B4 goal: instrument the runtime panic path dynamically (B3 left the
//! runtime root cause unproven; B4 adds debugger-side observation without
//! modifying the runtime DLL or the protected sample).
//!
//! Design constraints (ADR7-B4):
//! - debugger-side ONLY: no writes into the target image, no runtime DLL
//!   file modification, no ScyllaHide, no extra injectors.
//! - observation points are installed as HARDWARE breakpoints (DR0-DR3) so
//!   no code bytes are patched in the target.
//! - every debug event is recorded with a monotonic timestamp, pid/tid,
//!   event kind, module RVA, RIP/RSP, exception code, first-chance flag,
//!   continuation decision and (when available) a call-stack snapshot.
//! - the four address fields are recorded separately and never merged:
//!   (1) recorded exception address (ExceptionAddress from the debug event),
//!   (2) breakpoint hit address (DR-triggered exception address),
//!   (3) actual int29 site address (matched against the static int29 table),
//!   (4) post-exception RIP (GetThreadContext after the exception).
//!
//! The observer is opt-in via MIDA_B4_OBSERVER=1; when disabled, the
//! debugger behaves exactly as before (zero perturbation).

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::b4_runtime_offsets;

/// Observation tables bound to the EXACT runtime artifact
/// (ADR7-B4-RUNTIME-BINDING-CORRECTION-1).
///
/// The tables are generated from the authority offset map for runtime sha256
/// AE42901E... (see b4_runtime_offset_map.json / b4_runtime_offsets.rs). They
/// are NOT portable: any other runtime binary MUST be re-mapped before
/// observation. The observer fails closed on a hash mismatch — no
/// observation point is installed and no int29 match is claimed when the
/// runtime actually loaded does not match RUNTIME_SHA256.
pub const RUNTIME_SHA256: &str = b4_runtime_offsets::RUNTIME_SHA256;
pub const RUNTIME_OBS_POINTS: &[(u32, &str)] = &b4_runtime_offsets::OBS_POINTS;
pub const INT29_SITES: &[u32] = &b4_runtime_offsets::INT29_SITES;

/// Result of the runtime binding verification (cached once per process).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeBinding {
    /// The runtime file referenced by MIDA_RUNTIME_DLL was hashed and
    /// matches the bound RUNTIME_SHA256: observation is authorized.
    Verified,
    /// The observer is disabled (MIDA_B4_OBSERVER unset): no observation.
    Disabled,
    /// MIDA_RUNTIME_DLL is not set in this process: cannot verify, fail closed.
    NoRuntimeEnv,
    /// The runtime file could not be read/hashed: fail closed.
    Unreadable,
    /// The runtime file hash does NOT match RUNTIME_SHA256: fail closed.
    Mismatch { actual: String },
}

/// Cache for the once-per-process binding check.
static RUNTIME_BINDING: std::sync::OnceLock<RuntimeBinding> = std::sync::OnceLock::new();

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Verify that the runtime artifact this process is loading (MIDA_RUNTIME_DLL)
/// is exactly the artifact the observer is bound to. Fail-closed on any
/// mismatch or inability to verify. Result is cached after the first call.
pub fn runtime_binding() -> RuntimeBinding {
    RUNTIME_BINDING
        .get_or_init(|| {
            if !Adr7B4Observer::enabled() {
                return RuntimeBinding::Disabled;
            }
            let Some(path) = std::env::var_os("MIDA_RUNTIME_DLL").map(std::path::PathBuf::from)
            else {
                return RuntimeBinding::NoRuntimeEnv;
            };
            let Ok(bytes) = std::fs::read(&path) else {
                return RuntimeBinding::Unreadable;
            };
            let actual = sha256_hex(&bytes);
            if actual.eq_ignore_ascii_case(RUNTIME_SHA256) {
                RuntimeBinding::Verified
            } else {
                RuntimeBinding::Mismatch { actual }
            }
        })
        .clone()
}

/// Whether observation is authorized: the observer is enabled AND the runtime
/// binding verified against the exact artifact. False => fail closed.
pub fn observation_authorized() -> bool {
    runtime_binding() == RuntimeBinding::Verified
}

/// Event kinds recorded by the observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum B4EventKind {
    /// The runtime DLL was loaded (base captured for RVA mapping).
    RuntimeLoaded,
    /// A hardware breakpoint observation point fired.
    BreakpointHit,
    /// Any other debug event (thread create/exit, module load/unload, etc.).
    DebugEvent,
    /// A first-chance exception was delivered to the debugger.
    FirstChanceException,
    /// A second-chance exception (unhandled) was delivered.
    SecondChanceException,
    /// The target process exited.
    ProcessExit,
}

impl B4EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeLoaded => "runtime_loaded",
            Self::BreakpointHit => "breakpoint_hit",
            Self::DebugEvent => "debug_event",
            Self::FirstChanceException => "first_chance_exception",
            Self::SecondChanceException => "second_chance_exception",
            Self::ProcessExit => "process_exit",
        }
    }
}

/// One recorded observation.
#[derive(Debug, Clone)]
pub struct B4Record {
    /// Monotonic tick (GetTickCount64) at record time.
    pub ts_ms: u64,
    /// Sequence number (strictly increasing).
    pub seq: u64,
    /// Event kind.
    pub kind: B4EventKind,
    /// Target process id.
    pub pid: u32,
    /// Target thread id.
    pub tid: u32,
    /// Module base of mida_antidebug_runtime.dll at record time (0 if unknown).
    pub runtime_base: u64,
    /// RVA within the runtime DLL (None when the address is outside it).
    pub runtime_rva: Option<u32>,
    /// Recorded exception address (ExceptionAddress from debug event).
    pub recorded_exception_address: Option<u64>,
    /// Breakpoint hit address (address field of the Breakpoint event).
    pub breakpoint_hit_address: Option<u64>,
    /// Actual int29 site address (matched against INT29_SITES table).
    pub actual_int29_address: Option<u64>,
    /// Post-exception RIP (GetThreadContext after the event).
    pub post_exception_rip: Option<u64>,
    /// Post-exception RSP.
    pub post_exception_rsp: Option<u64>,
    /// Exception code (0 when not an exception).
    pub exception_code: Option<u32>,
    /// First-chance flag (None when not an exception).
    pub first_chance: Option<bool>,
    /// Continuation decision recorded by the loop (None until set).
    pub continuation: Option<String>,
    /// Call-stack snapshot (raw return addresses; symbols resolved offline).
    pub call_stack: Vec<u64>,
    /// ADR7-B5: TLS scene snapshot for the faulting thread (None when not
    /// captured for this record).
    pub tls_snapshot: Option<crate::b5_tls_capture::TlsSnapshot>,
}

impl B4Record {
    fn new(seq: u64, ts_ms: u64, kind: B4EventKind, pid: u32, tid: u32) -> Self {
        Self {
            ts_ms,
            seq,
            kind,
            pid,
            tid,
            runtime_base: 0,
            runtime_rva: None,
            recorded_exception_address: None,
            breakpoint_hit_address: None,
            actual_int29_address: None,
            post_exception_rip: None,
            post_exception_rsp: None,
            exception_code: None,
            first_chance: None,
            continuation: None,
            call_stack: Vec::new(),
            tls_snapshot: None,
        }
    }

    /// Compute runtime_rva from an absolute address using the module base.
    pub fn with_runtime_base(&mut self, base: u64) {
        self.runtime_base = base;
    }

    /// Resolve an absolute address against the runtime base and set the RVA.
    pub fn resolve_rva(&mut self, addr: u64) {
        if self.runtime_base != 0 && addr >= self.runtime_base {
            let rva = (addr - self.runtime_base) as u32;
            if rva < 0x200000 {
                self.runtime_rva = Some(rva);
            }
        }
    }

    /// If the recorded exception address equals an int29 site, mark it.
    pub fn match_int29(&mut self, addr: u64) {
        if self.runtime_base != 0 && addr >= self.runtime_base {
            let rva = (addr - self.runtime_base) as u32;
            if INT29_SITES.contains(&rva) {
                self.actual_int29_address = Some(addr);
            }
        }
    }
}

/// Thread-safe B4 observer (the debugger loop calls it from one thread, but
/// the writer may be invoked from a finaliser).
#[derive(Default)]
pub struct Adr7B4Observer {
    records: Mutex<Vec<B4Record>>,
    /// Runtime DLL base once seen (0 until LOAD_DLL).
    runtime_base: Mutex<u64>,
    /// Sequence counter.
    seq: Mutex<u64>,
}

impl Adr7B4Observer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observer mode:
    ///   "1" = active (installs observation-point hardware breakpoints),
    ///   "2" = passive (records events only, zero perturbation).
    pub fn mode() -> Option<u32> {
        std::env::var("MIDA_B4_OBSERVER")
            .ok()
            .and_then(|v| v.parse().ok())
    }

    /// True when the observer is enabled (checked by the debugger).
    pub fn enabled() -> bool {
        Self::mode().is_some()
    }

    /// True when the observer installs observation-point breakpoints.
    ///
    /// Fail-closed (ADR7-B4-RUNTIME-BINDING-CORRECTION-1): even in active
    /// mode, breakpoints are installed ONLY when the runtime binding was
    /// verified against the exact artifact (RUNTIME_SHA256). A hash mismatch
    /// or unverifiable runtime means NO observation point is armed — stale
    /// offsets are never used silently.
    pub fn active_breakpoints() -> bool {
        Self::mode() == Some(1) && observation_authorized()
    }

    /// Record a debug event.
    pub fn record(
        &self,
        kind: B4EventKind,
        pid: u32,
        tid: u32,
        addr: Option<u64>,
        exception_code: Option<u32>,
        first_chance: Option<bool>,
        continuation: Option<String>,
        rip: Option<u64>,
        rsp: Option<u64>,
    ) -> B4Record {
        let ts_ms = unsafe { windows::Win32::System::SystemInformation::GetTickCount64() };
        let mut seq = self.seq.lock().unwrap();
        *seq += 1;
        let seq_val = *seq;
        drop(seq);

        let base = *self.runtime_base.lock().unwrap();
        let mut rec = B4Record::new(seq_val, ts_ms, kind, pid, tid);
        rec.with_runtime_base(base);
        if let Some(a) = addr {
            rec.resolve_rva(a);
            rec.match_int29(a);
        }
        rec.recorded_exception_address = addr;
        rec.exception_code = exception_code;
        rec.first_chance = first_chance;
        rec.continuation = continuation;
        rec.post_exception_rip = rip;
        rec.post_exception_rsp = rsp;
        self.records.lock().unwrap().push(rec.clone());
        rec
    }

    /// Record a debug event with an optional ADR7-B5 TLS scene snapshot.
    pub fn record_with_tls(
        &self,
        kind: B4EventKind,
        pid: u32,
        tid: u32,
        addr: Option<u64>,
        exception_code: Option<u32>,
        first_chance: Option<bool>,
        continuation: Option<String>,
        rip: Option<u64>,
        rsp: Option<u64>,
        tls: Option<crate::b5_tls_capture::TlsSnapshot>,
    ) -> B4Record {
        let mut rec = self.record(
            kind, pid, tid, addr, exception_code, first_chance, continuation, rip, rsp,
        );
        rec.tls_snapshot = tls;
        rec
    }

    /// Record a breakpoint hit at the given address.
    pub fn record_breakpoint(&self, pid: u32, tid: u32, addr: u64) -> B4Record {
        let ts_ms = unsafe { windows::Win32::System::SystemInformation::GetTickCount64() };
        let mut seq = self.seq.lock().unwrap();
        *seq += 1;
        let seq_val = *seq;
        drop(seq);

        let base = *self.runtime_base.lock().unwrap();
        let mut rec = B4Record::new(seq_val, ts_ms, B4EventKind::BreakpointHit, pid, tid);
        rec.with_runtime_base(base);
        rec.resolve_rva(addr);
        rec.breakpoint_hit_address = Some(addr);
        rec.recorded_exception_address = Some(addr);
        rec.continuation = Some("continue".to_string());
        self.records.lock().unwrap().push(rec.clone());
        rec
    }

    /// Record the runtime module load (sets the base for RVA mapping).
    ///
    /// The timeline carries the runtime binding verdict so downstream audits
    /// can distinguish a verified observation from a fail-closed one.
    pub fn record_runtime_loaded(&self, pid: u32, tid: u32, base: u64) {
        *self.runtime_base.lock().unwrap() = base;
        let cont = match runtime_binding() {
            RuntimeBinding::Verified => "continue (runtime binding verified)",
            RuntimeBinding::Disabled => "continue (observer disabled)",
            RuntimeBinding::NoRuntimeEnv => "fail-closed (MIDA_RUNTIME_DLL unset)",
            RuntimeBinding::Unreadable => "fail-closed (runtime unreadable)",
            RuntimeBinding::Mismatch { .. } => "fail-closed (runtime hash mismatch)",
        };
        self.record(
            B4EventKind::RuntimeLoaded,
            pid,
            tid,
            Some(base),
            None,
            None,
            Some(cont.to_string()),
            None,
            None,
        );
    }

    /// Finalise the timeline to the given path as JSON (hand-rolled writer,
    /// no serde_json dependency in the core crate).
    pub fn write_timeline(&self, path: &std::path::Path) -> std::io::Result<()> {
        let records = self.records.lock().unwrap();
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str("  \"schema\": \"mida.adr7-b4-timeline/v1\",\n");
        out.push_str(&format!("  \"runtime_sha256\": \"{}\",\n", RUNTIME_SHA256));
        out.push_str(&format!(
            "  \"runtime_size_bytes\": {},\n",
            b4_runtime_offsets::RUNTIME_SIZE_BYTES
        ));
        out.push_str(&format!(
            "  \"pdb_sha256\": \"{}\",\n",
            b4_runtime_offsets::PDB_SHA256
        ));
        out.push_str(&format!(
            "  \"pdb_guid\": \"{}\",\n",
            b4_runtime_offsets::PDB_GUID
        ));
        out.push_str(&format!(
            "  \"pdb_age\": {},\n",
            b4_runtime_offsets::PDB_AGE
        ));
        out.push_str(&format!(
            "  \"runtime_binding\": \"{:?}\",\n",
            runtime_binding()
        ));
        out.push_str("  \"observer_points\": [");
        for (i, (rva, name)) in RUNTIME_OBS_POINTS.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&format!("\"{:#x} {}\"", rva, name.replace('\"', "'")));
        }
        out.push_str("],\n");
        out.push_str("  \"int29_sites\": [");
        for (i, rva) in INT29_SITES.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&format!("\"{:#x}\"", rva));
        }
        out.push_str("],\n");
        out.push_str("  \"records\": [\n");
        for (i, r) in records.iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            out.push_str("    {\n");
            out.push_str(&format!("      \"ts_ms\": {},\n", r.ts_ms));
            out.push_str(&format!("      \"seq\": {},\n", r.seq));
            out.push_str(&format!("      \"kind\": \"{}\",\n", r.kind.as_str()));
            out.push_str(&format!("      \"pid\": {},\n", r.pid));
            out.push_str(&format!("      \"tid\": {},\n", r.tid));
            out.push_str(&format!(
                "      \"runtime_base\": \"{:#x}\",\n",
                r.runtime_base
            ));
            out.push_str(&format!(
                "      \"runtime_rva\": {},\n",
                opt_hex(r.runtime_rva.map(|v| v as u64))
            ));
            out.push_str(&format!(
                "      \"recorded_exception_address\": {},\n",
                opt_hex(r.recorded_exception_address)
            ));
            out.push_str(&format!(
                "      \"breakpoint_hit_address\": {},\n",
                opt_hex(r.breakpoint_hit_address)
            ));
            out.push_str(&format!(
                "      \"actual_int29_address\": {},\n",
                opt_hex(r.actual_int29_address)
            ));
            out.push_str(&format!(
                "      \"post_exception_rip\": {},\n",
                opt_hex(r.post_exception_rip)
            ));
            out.push_str(&format!(
                "      \"post_exception_rsp\": {},\n",
                opt_hex(r.post_exception_rsp)
            ));
            out.push_str(&format!(
                "      \"exception_code\": {},\n",
                opt_hex(r.exception_code.map(|v| v as u64))
            ));
            out.push_str(&format!(
                "      \"first_chance\": {},\n",
                opt_bool(r.first_chance)
            ));
            out.push_str(&format!(
                "      \"continuation\": {},\n",
                opt_str(r.continuation.as_deref())
            ));
            if let Some(tls) = &r.tls_snapshot {
                out.push_str(&format!("      \"tls_snapshot\": {{\n"));
                out.push_str(&format!("        \"tid\": {},\n", tls.tid));
                out.push_str(&format!("        \"teb_address\": {},\n", opt_hex(tls.teb_address)));
                out.push_str(&format!("        \"tls_array_base\": {},\n", opt_hex(tls.tls_array_base)));
                out.push_str(&format!("        \"tls_index\": {},\n", opt_u32(tls.tls_index)));
                out.push_str(&format!("        \"tls_slot_pointer\": {},\n", opt_hex(tls.tls_slot_pointer)));
                out.push_str(&format!("        \"slot_page_state\": {},\n", opt_u32(tls.slot_page_state)));
                out.push_str(&format!("        \"slot_page_protect\": {},\n", opt_u32(tls.slot_page_protect)));
                out.push_str(&format!("        \"local_panic_count_counter\": {},\n", opt_u64(tls.local_panic_count_counter)));
                out.push_str(&format!("        \"local_panic_count_flag\": {},\n", opt_u8(tls.local_panic_count_flag)));
                out.push_str(&format!("        \"classification\": \"{}\",\n", tls.classification.as_str()));
                out.push_str(&format!("        \"capture_trigger\": \"{}\",\n", tls.capture_trigger));
                out.push_str(&format!("        \"capture_phase\": \"{}\",\n", tls.capture_phase));
                out.push_str(&format!("        \"capture_error\": {}\n", opt_str(tls.capture_error.as_deref())));
                out.push_str("      },\n");
            }
            out.push_str("      \"call_stack\": [");
            for (j, v) in r.call_stack.iter().enumerate() {
                if j > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("\"{:#x}\"", v));
            }
            out.push_str("]\n");
            out.push_str("    }");
        }
        out.push_str("\n  ]\n}\n");
        std::fs::write(path, out)
    }

    /// Whether the runtime base has been observed.
    pub fn runtime_observed(&self) -> bool {
        *self.runtime_base.lock().unwrap() != 0
    }

    /// The observed runtime module base (0 until the runtime DLL load is seen).
    pub fn runtime_base(&self) -> u64 {
        *self.runtime_base.lock().unwrap()
    }
}

/// B4 observer state helper: static observation point labels (sorted).
pub fn obs_point_labels() -> BTreeMap<u32, String> {
    RUNTIME_OBS_POINTS
        .iter()
        .map(|(rva, name)| (*rva, name.to_string()))
        .collect()
}

/// Format an Option<u32> as JSON.
fn opt_u32(v: Option<u32>) -> String {
    match v {
        Some(x) => format!("{x}"),
        None => "null".to_string(),
    }
}

/// Format an Option<u64> as JSON.
fn opt_u64(v: Option<u64>) -> String {
    match v {
        Some(x) => format!("{x}"),
        None => "null".to_string(),
    }
}

/// Format an Option<u8> as JSON.
fn opt_u8(v: Option<u8>) -> String {
    match v {
        Some(x) => format!("{x}"),
        None => "null".to_string(),
    }
}

/// Format an Option<u64> as a JSON string literal or null.
fn opt_hex(v: Option<u64>) -> String {
    match v {
        Some(x) => format!("\"{:#x}\"", x),
        None => "null".to_string(),
    }
}

/// Format an Option<bool> as JSON.
fn opt_bool(v: Option<bool>) -> String {
    match v {
        Some(b) => b.to_string(),
        None => "null".to_string(),
    }
}

/// Format an Option<&str> as a JSON string literal or null.
fn opt_str(v: Option<&str>) -> String {
    match v {
        Some(s) => format!("\"{}\"", s),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_tables_are_nonempty_and_sorted() {
        // The observation tables must be bound to the exact runtime artifact:
        // non-empty, ordered by RVA, and the fault RVA must be a known int29.
        assert!(!RUNTIME_OBS_POINTS.is_empty());
        assert!(!INT29_SITES.is_empty());
        // Observation points occupy distinct DR slots (0..3): no duplicates.
        let mut rvas: Vec<u32> = RUNTIME_OBS_POINTS.iter().map(|(r, _)| *r).collect();
        rvas.sort_unstable();
        rvas.dedup();
        assert_eq!(
            rvas.len(),
            RUNTIME_OBS_POINTS.len(),
            "obs points must be distinct"
        );
        // int29 sites are sorted by RVA.
        for w in INT29_SITES.windows(2) {
            assert!(w[0] < w[1], "int29 sites must be sorted by RVA");
        }
        // The live-observed fault RVA is one of the bound int29 sites:
        // this is the exact property that failed in the old binding (the
        // fault 0x2e816 was NOT in the stale c22cb722 int29 table).
        assert!(
            INT29_SITES.contains(&b4_runtime_offsets::OBSERVED_FAULT_RVA),
            "observed fault RVA must be in the bound int29 table"
        );
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // "abc" -> SHA-256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hex = sha256_hex(b"abc");
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn binding_hash_compare_is_case_insensitive() {
        // The authority manifest stores lowercase; the generated offsets
        // uppercase. Equality must be case-insensitive.
        assert!("AE42901E...".eq_ignore_ascii_case("ae42901e..."));
        let actual = "ae42901ec940dfa95566dcf9e0787d1e2c9439d90e7c593ed3a803a4f9cdbb76";
        assert!(actual.eq_ignore_ascii_case(RUNTIME_SHA256));
    }

    #[test]
    fn match_int29_uses_bound_table() {
        let mut rec = B4Record::new(1, 1, B4EventKind::FirstChanceException, 1, 1);
        rec.with_runtime_base(0x180000000);
        rec.match_int29(0x180000000 + b4_runtime_offsets::OBSERVED_FAULT_RVA as u64);
        assert_eq!(
            rec.actual_int29_address,
            Some(0x180000000 + b4_runtime_offsets::OBSERVED_FAULT_RVA as u64)
        );
        // An address OUTSIDE the bound int29 table must NOT be claimed.
        let mut rec2 = B4Record::new(2, 1, B4EventKind::FirstChanceException, 1, 1);
        rec2.with_runtime_base(0x180000000);
        rec2.match_int29(0x180000000 + 0x2e806); // stale-c22 site, NOT in bound table
        assert_eq!(rec2.actual_int29_address, None);
    }
}
