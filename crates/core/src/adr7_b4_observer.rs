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

/// Static observation table derived from ADR7-B3 (verified against the
/// committed runtime c22cb722 via dumpbin disassembly).
pub const RUNTIME_OBS_POINTS: &[(u32, &str)] = &[
    (0x2ed90, "panic_count::increase entry"),
    (0x2edb6, "panic_count::increase+0x26 (B3 fault RVA)"),
    (0x2e5f4, "panic_with_hook entry"),
    (0x2e628, "panic_with_hook -> panic_count::increase call site"),
];

/// Static int29 (__fastfail) sites from ADR7-B3, verified via dumpbin.
/// All sites are `CD 29` with `mov ecx,7` (FAST_FAIL_FATAL_APP_EXIT).
pub const INT29_SITES: &[u32] = &[
    0x2bfb1, 0x2c356, 0x2c589, 0x2c749, 0x2d060, 0x2e7d8, 0x2e806, 0x3f31c,
    0x3faa7,
];

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
    pub fn active_breakpoints() -> bool {
        Self::mode() == Some(1)
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
    pub fn record_runtime_loaded(&self, pid: u32, tid: u32, base: u64) {
        *self.runtime_base.lock().unwrap() = base;
        self.record(
            B4EventKind::RuntimeLoaded,
            pid,
            tid,
            Some(base),
            None,
            None,
            Some("continue".to_string()),
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
        out.push_str("  \"runtime_sha256\": \"c22cb722ecae379d09ee372216d4697b13e371e0c280fb352d01a7fd1208a710\",\n");
        out.push_str("  \"observer_points\": [");
        for (i, (rva, name)) in RUNTIME_OBS_POINTS.iter().enumerate() {
            if i > 0 { out.push_str(", "); }
            out.push_str(&format!("\"{:#x} {}\"", rva, name.replace('\"', "'")));
        }
        out.push_str("],\n");
        out.push_str("  \"int29_sites\": [");
        for (i, rva) in INT29_SITES.iter().enumerate() {
            if i > 0 { out.push_str(", "); }
            out.push_str(&format!("\"{:#x}\"", rva));
        }
        out.push_str("],\n");
        out.push_str("  \"records\": [\n");
        for (i, r) in records.iter().enumerate() {
            if i > 0 { out.push_str(",\n"); }
            out.push_str("    {\n");
            out.push_str(&format!("      \"ts_ms\": {},\n", r.ts_ms));
            out.push_str(&format!("      \"seq\": {},\n", r.seq));
            out.push_str(&format!("      \"kind\": \"{}\",\n", r.kind.as_str()));
            out.push_str(&format!("      \"pid\": {},\n", r.pid));
            out.push_str(&format!("      \"tid\": {},\n", r.tid));
            out.push_str(&format!("      \"runtime_base\": \"{:#x}\",\n", r.runtime_base));
            out.push_str(&format!("      \"runtime_rva\": {},\n", opt_hex(r.runtime_rva.map(|v| v as u64))));
            out.push_str(&format!("      \"recorded_exception_address\": {},\n", opt_hex(r.recorded_exception_address)));
            out.push_str(&format!("      \"breakpoint_hit_address\": {},\n", opt_hex(r.breakpoint_hit_address)));
            out.push_str(&format!("      \"actual_int29_address\": {},\n", opt_hex(r.actual_int29_address)));
            out.push_str(&format!("      \"post_exception_rip\": {},\n", opt_hex(r.post_exception_rip)));
            out.push_str(&format!("      \"post_exception_rsp\": {},\n", opt_hex(r.post_exception_rsp)));
            out.push_str(&format!("      \"exception_code\": {},\n", opt_hex(r.exception_code.map(|v| v as u64))));
            out.push_str(&format!("      \"first_chance\": {},\n", opt_bool(r.first_chance)));
            out.push_str(&format!("      \"continuation\": {},\n", opt_str(r.continuation.as_deref())));
            out.push_str("      \"call_stack\": [");
            for (j, v) in r.call_stack.iter().enumerate() {
                if j > 0 { out.push_str(", "); }
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
}

/// B4 observer state helper: static observation point labels (sorted).
pub fn obs_point_labels() -> BTreeMap<u32, String> {
    RUNTIME_OBS_POINTS
        .iter()
        .map(|(rva, name)| (*rva, name.to_string()))
        .collect()
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
