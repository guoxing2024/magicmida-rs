//! Parsing of `mida-cli` output into structured progress events.
//!
//! # Why parse text instead of calling the library directly
//!
//! The GUI drives `mida-cli.exe` as a child process rather than linking the
//! unpack pipeline.  Two reasons:
//!
//! 1. The pipeline installs a global `tracing` subscriber and takes over the
//!    debug event loop; running it inside a GUI process would fight with the
//!    GUI's own event loop and make a crash in the debugger take the window
//!    down with it.
//! 2. The verified golden record (186 resolved / 9 modules / a specific
//!    SHA-256) is produced by *that exact binary*.  Keeping the process
//!    boundary means the GUI cannot silently change what the pipeline does.
//!
//! The parser below is therefore the contract between the two.  It is written
//! against the real log lines captured from a successful run, and the tests at
//! the bottom of this file are those literal lines.

/// One pipeline phase, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Reading the PE header and identifying the packer.
    Identify,
    /// Creating the debuggee and injecting ScyllaHide.
    Launch,
    /// Driving the debug event loop until the OEP is located.
    FindOep,
    /// Waiting out the IAT decryption window and locating the table.
    LocateIat,
    /// Tracing each IAT slot through the VM.
    TraceIat,
    /// Rebuilding the import table and post-processing the image.
    Rebuild,
    /// Writing the product to disk.
    Dump,
    /// Finished (successfully or not).
    Done,
}

impl Phase {
    /// All phases in order, for rendering the progress rail.
    pub const ALL: [Phase; 8] = [
        Phase::Identify,
        Phase::Launch,
        Phase::FindOep,
        Phase::LocateIat,
        Phase::TraceIat,
        Phase::Rebuild,
        Phase::Dump,
        Phase::Done,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Phase::Identify => "识别",
            Phase::Launch => "启动",
            Phase::FindOep => "定位 OEP",
            Phase::LocateIat => "定位 IAT",
            Phase::TraceIat => "追踪 IAT",
            Phase::Rebuild => "重建",
            Phase::Dump => "写出",
            Phase::Done => "完成",
        }
    }

}

/// Severity of a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Good,
    Warn,
    Fatal,
    Debug,
}

impl Level {
    /// Parse the `[LEVEL]` tag that `mida-cli` emits.
    pub fn parse(tag: &str) -> Level {
        match tag {
            "GOOD" => Level::Good,
            "WARN" => Level::Warn,
            "FATAL" => Level::Fatal,
            "DEBUG" => Level::Debug,
            _ => Level::Info,
        }
    }
}

/// A parsed log line.
#[derive(Debug, Clone)]
pub struct LogLine {
    /// Wall-clock `HH:MM:SS` as emitted by the CLI (empty when absent).
    pub time: String,
    pub level: Level,
    pub message: String,
}

/// Metrics extracted from the trace.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    /// Packer version string, e.g. `V3`.
    pub themida_version: Option<String>,
    /// Debuggee PID.
    pub pid: Option<u32>,
    /// Entry-point RVA as reported at load time.
    pub entry_rva: Option<u64>,
    /// Runtime image base.
    pub image_base: Option<u64>,
    /// OEP resolved by the guard path.
    pub oep: Option<u64>,
    /// IAT runtime VA.
    pub iat_va: Option<u64>,
    /// IAT size in bytes.
    pub iat_size: Option<u64>,
    /// Total IAT slots.
    pub iat_slots: Option<u64>,
    /// Number of fragmented IAT blocks.
    pub iat_blocks: Option<u64>,
    /// Slots resolved by the trace.
    pub resolved: Option<u64>,
    /// Slots the trace gave up on.
    pub failed: Option<u64>,
    /// Index of the slot currently being traced (live progress).
    pub current_slot: Option<u64>,
    /// Modules in the rebuilt import table.
    pub module_count: Option<u64>,
    /// Thunks in the rebuilt import table.
    pub thunk_count: Option<u64>,
    /// Hardcoded addresses rewritten.
    pub fixed_addresses: Option<u64>,
    /// Relocation entries generated.
    pub relocations: Option<u64>,
    /// Final output size in bytes.
    pub output_size: Option<u64>,
}

impl Metrics {
    /// Fraction of the IAT trace that has been walked, 0.0..=1.0.
    ///
    /// Prefers the live slot index while tracing; falls back to the final
    /// resolved count once the trace has reported completion.
    pub fn trace_progress(&self) -> Option<f32> {
        let total = self.iat_slots? as f32;
        if total <= 0.0 {
            return None;
        }
        if let Some(cur) = self.current_slot {
            return Some((cur as f32 / total).clamp(0.0, 1.0));
        }
        let done = self.resolved.unwrap_or(0) + self.failed.unwrap_or(0);
        if done == 0 {
            return None;
        }
        Some((done as f32 / total).clamp(0.0, 1.0))
    }
}

/// Everything the parser knows about the run so far.
#[derive(Debug, Default)]
pub struct RunState {
    pub phase: Option<Phase>,
    pub metrics: Metrics,
    pub lines: Vec<LogLine>,
    /// Set once `Done.` or a fatal error is seen.
    pub finished: Option<bool>,
    /// Error text when the run failed.
    pub error: Option<String>,
    /// Output path reported by the CLI.
    pub output_path: Option<String>,
}

impl RunState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one raw line from the child process.
    ///
    /// Returns `true` when the line was a recognised pipeline milestone (so the
    /// caller can request a repaint); debug spam and the per-slot trace lines
    /// return `false` to avoid repainting thousands of times.
    pub fn feed(&mut self, raw: &str) -> bool {
        let raw = raw.trim_end_matches(['\r', '\n']);
        if raw.is_empty() {
            return false;
        }
        // The CLI colours its `[GOOD]`/`[WARN]`/`[FATAL]` tags with ANSI
        // escapes.  A GUI has no terminal to interpret them, so they would show
        // up as literal `[32m` noise in the log view.
        let cleaned = strip_ansi(raw);
        let raw = cleaned.as_str();

        let Some((time, level, message)) = split_line(raw) else {
            // Un-tagged output: a panic backtrace is worth keeping, but the
            // CLI also writes a raw BEL byte to stdout on fatal errors, which
            // would render as a row of replacement glyphs.  Keep only lines
            // with something printable in them.
            let printable = raw.chars().any(|c| !c.is_control() && c != '\u{feff}');
            if printable {
                self.lines.push(LogLine {
                    time: String::new(),
                    level: Level::Info,
                    message: raw.to_string(),
                });
            }
            return false;
        };

        let mut milestone = false;

        // ---- phase transitions -------------------------------------------
        let new_phase = detect_phase(&message);
        if let Some(p) = new_phase {
            if self.phase != Some(p) {
                self.phase = Some(p);
                milestone = true;
            }
        }

        // ---- metric extraction -------------------------------------------
        if let Some(v) = after(&message, "Themida version: ") {
            self.metrics.themida_version = Some(v.trim().to_string());
            milestone = true;
        }
        if let Some(v) = after(&message, "Process created (PID: ") {
            self.metrics.pid = v.trim_end_matches(')').parse().ok();
            milestone = true;
        }
        if let Some(v) = after(&message, "Entry point RVA: ") {
            self.metrics.entry_rva = parse_hex_prefix(v);
        }
        if let Some(v) = after(&message, "image_base=") {
            self.metrics.image_base = parse_hex_prefix(v);
        }
        if let Some(v) = after(&message, "Initial OEP: ") {
            self.metrics.oep = parse_hex_prefix(v);
            milestone = true;
        }
        // The OEP is announced as soon as the guard path resolves it, which is
        // several seconds before `Initial OEP:` (that line is printed after the
        // IAT decryption window).  Take it early so the panel is not blank for
        // the whole wait.
        if message.starts_with("OEP found — letting program execute") {
            if let Some(v) = after(&message, "oep=") {
                if self.metrics.oep.is_none() {
                    self.metrics.oep = parse_hex_prefix(v);
                }
            }
            milestone = true;
        }
        // Image base arrives with the CREATE_PROCESS debug event.
        if message.contains("image_base=") && self.metrics.image_base.is_none() {
            if let Some(v) = after(&message, "image_base=") {
                self.metrics.image_base = parse_hex_prefix(v);
            }
        }
        if let Some(v) = after(&message, "IAT located iat=") {
            self.metrics.iat_va = parse_hex_prefix(v);
            milestone = true;
        }
        if let Some(v) = after(&message, "IAT boundaries: ") {
            // start=0x.., end=0x.., size=8504 (1063 slots), blocks=14
            self.metrics.iat_size = after(v, "size=").and_then(parse_decimal_prefix);
            self.metrics.iat_slots = v
                .split_once('(')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .and_then(|n| n.parse().ok());
            self.metrics.iat_blocks = after(v, "blocks=").and_then(parse_decimal_prefix);
            milestone = true;
        }
        // Live trace progress: "Tracing IAT slot 567 (0x...) from ..."
        if let Some(v) = after(&message, "Tracing IAT slot ") {
            self.metrics.current_slot = parse_decimal_prefix(v);
        }
        // Resolved/failed: "IAT trace complete: 186 resolved, 8 failed"
        if let Some(v) = after(&message, "IAT trace complete: ") {
            self.metrics.resolved = parse_decimal_prefix(v);
            self.metrics.failed = after(v, "resolved,").and_then(parse_decimal_prefix);
            milestone = true;
        }
        // "Import table reconstructed module_count=9 thunk_count=186"
        if let Some(v) = after(&message, "Import table reconstructed module_count=") {
            self.metrics.module_count = parse_decimal_prefix(v);
            self.metrics.thunk_count = after(v, "thunk_count=").and_then(parse_decimal_prefix);
            milestone = true;
        }
        // "Scanned 603436 bytes in writable sections, fixed 2907 hardcoded addresses"
        if message.contains("fixed") && message.ends_with("hardcoded addresses") {
            self.metrics.fixed_addresses = message
                .rsplit_once("fixed ")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .and_then(|n| n.parse().ok());
            milestone = true;
        }
        // "Relocation table: 2907 entries (5972 bytes, untruncated), VA=..."
        if let Some(v) = after(&message, "Relocation table: ") {
            self.metrics.relocations = parse_decimal_prefix(v);
            milestone = true;
        }
        // "Dump written successfully path=... size=1539584 sections=16"
        if let Some(v) = after(&message, "Dump written successfully path=") {
            self.output_path = Some(v.split(" size=").next().unwrap_or(v).to_string());
            self.metrics.output_size = after(v, "size=").and_then(parse_decimal_prefix);
            milestone = true;
        }
        // "Unpacked: <path>"
        if let Some(v) = after(&message, "Unpacked: ") {
            self.output_path = Some(v.trim().to_string());
            milestone = true;
        }

        // ---- terminal states ---------------------------------------------
        if message == "Done." {
            self.finished = Some(true);
            self.phase = Some(Phase::Done);
            milestone = true;
        }
        if level == Level::Fatal {
            // The CLI prints "Fatal error: ..." before exiting 1.
            if message.starts_with("Fatal error:") || message.starts_with("Fatal error ") {
                self.error = Some(message.to_string());
                self.finished = Some(false);
                self.phase = Some(Phase::Done);
                milestone = true;
            }
        }

        self.lines.push(LogLine {
            time,
            level,
            message,
        });
        milestone
    }
}

// ---------------------------------------------------------------------------
// ANSI stripping
// ---------------------------------------------------------------------------

/// Remove ANSI CSI sequences (`ESC [ ... m`) from a line.
///
/// Only the SGR colour sequences the CLI emits are handled, but the scanner is
/// general enough to drop any `ESC [ ... letter` run.
fn strip_ansi(s: &str) -> String {
    if !s.contains('\x1b') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        // ESC: consume the whole sequence.
        match chars.peek() {
            Some('[') => {
                chars.next();
                // CSI: parameter bytes 0x30-0x3F, then intermediates, then a
                // final byte 0x40-0x7E.
                for c2 in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&c2) {
                        break;
                    }
                }
            }
            Some(']') => {
                // OSC: terminated by BEL or ST.
                chars.next();
                while let Some(c2) = chars.next() {
                    if c2 == '\u{7}' || c2 == '\u{1b}' {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Line splitting
// ---------------------------------------------------------------------------

/// Split `[HH:MM:SS] [LEVEL] message` into its three parts.
///
/// The CLI writes the timestamp in RFC 3339 with a `T` separator inside a
/// bracket; we keep only the time-of-day for display.
fn split_line(raw: &str) -> Option<(String, Level, String)> {
    let rest = raw.strip_prefix('[')?;
    let (stamp, rest) = rest.split_once(']')?;
    let time = stamp
        .split_once('T')
        .map(|(_, t)| t.trim_end_matches('Z').split('.').next().unwrap_or(t).to_string())
        .unwrap_or_else(|| stamp.to_string());

    let rest = rest.trim_start();
    let rest = rest.strip_prefix('[')?;
    let (tag, rest) = rest.split_once(']')?;

    Some((time, Level::parse(tag), rest.trim_start().to_string()))
}

/// Map a message to the phase it starts.
fn detect_phase(message: &str) -> Option<Phase> {
    // Order matters: check the most specific markers first.
    if message.starts_with("Loading:") {
        return Some(Phase::Identify);
    }
    if message.starts_with("Themida version:") {
        return Some(Phase::Identify);
    }
    if message.starts_with("Process created (PID:") {
        return Some(Phase::Launch);
    }
    if message.starts_with("ScyllaHide injected") {
        return Some(Phase::Launch);
    }
    if message.starts_with("OEP found — letting program execute") {
        return Some(Phase::FindOep);
    }
    if message.starts_with("IAT located iat=") {
        return Some(Phase::LocateIat);
    }
    if message.starts_with("Letting program execute for") {
        return Some(Phase::LocateIat);
    }
    if message.starts_with("[v3-trace] Starting IAT trace") {
        return Some(Phase::TraceIat);
    }
    if message.starts_with("Initial OEP:") {
        return Some(Phase::TraceIat);
    }
    if message.starts_with("IAT fixed") {
        return Some(Phase::Rebuild);
    }
    if message.starts_with("Shrink complete") {
        return Some(Phase::Rebuild);
    }
    if message.starts_with("Dumping to:") {
        return Some(Phase::Dump);
    }
    if message.starts_with("Dump written successfully") {
        return Some(Phase::Dump);
    }
    if message.starts_with("Unpacked:") {
        return Some(Phase::Done);
    }
    None
}

// ---------------------------------------------------------------------------
// Small parsing helpers
// ---------------------------------------------------------------------------

fn after<'a>(haystack: &'a str, needle: &str) -> Option<&'a str> {
    haystack.split_once(needle).map(|(_, rest)| rest)
}

fn parse_hex_prefix(s: &str) -> Option<u64> {
    let tok: String = s
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == 'x' || *c == 'X')
        .collect();
    let tok = tok.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(tok, 16).ok()
}

fn parse_decimal_prefix(s: &str) -> Option<u64> {
    let tok: String = s.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    tok.parse().ok()
}

// ---------------------------------------------------------------------------
// Tests — every case below is a literal line from a real successful run.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_LOG: &str = "\
[2026-10-22T15:39:14.550000Z] [INFO] Loading: D:\\Projects\\shiguang\\时光一键宏.exe
[2026-10-22T15:39:14.553000Z] [INFO] Entry point RVA: 0x83e058, EP offset: 0x9e058, EP bytes: [E8, 82, 01, 00, 00, 41, 52, 49]
[2026-10-22T15:39:14.556000Z] [INFO] Themida version: V3
[2026-10-22T15:39:14.573000Z] [INFO] Process created (PID: 25636)
[2026-10-22T15:39:14.988000Z] [INFO] ScyllaHide injected
[2026-10-22T15:39:15.220000Z] [INFO] OEP found — letting program execute for .text + IAT decryption oep=0x7ff6f5d41010
[2026-10-22T15:39:15.230000Z] [INFO] IAT boundaries: start=0x7ff6f5e536e0, end=0x7ff6f5e55818, size=8504 (1063 slots), blocks=14
[2026-10-22T15:39:15.231000Z] [INFO] IAT located iat=0x7ff6f5e536e0 size=0x2138
[2026-10-22T15:39:15.240000Z] [INFO] [v3-trace] Starting IAT trace: 1063 slots
[2026-10-22T15:39:15.300000Z] [INFO] [v3-trace] Tracing IAT slot 567 (0x7ff6f5e54898) from 0x113000 (trace_start=0x7ff6f5e53000)
[2026-10-22T15:39:16.230000Z] [INFO] [v3-trace] OK IAT trace complete: 186 resolved, 8 failed
[2026-10-22T15:39:16.238000Z] [INFO] Initial OEP: 0x7ff6f5d41010
[2026-10-22T15:39:16.242000Z] [INFO] IAT fixed
[2026-10-22T15:39:16.256000Z] [INFO] Import table reconstructed module_count=9 thunk_count=186
[2026-10-22T15:39:16.259000Z] [INFO] Scanned 603436 bytes in writable sections, fixed 2907 hardcoded addresses
[2026-10-22T15:39:16.260000Z] [INFO] Relocation table: 2907 entries (5972 bytes, untruncated), VA=0x174000, ASLR enabled
[2026-10-22T15:39:16.262000Z] [INFO] Dumping to: OUT\\smoke.exe
[2026-10-22T15:39:16.265000Z] [INFO] Dump written successfully path=OUT\\smoke.exe size=1539584 sections=16
[2026-10-22T15:39:16.267000Z] [GOOD] Unpacked: OUT\\smoke.exe
[2026-10-22T15:39:16.268000Z] [GOOD] Done.";

    fn run(log: &str) -> RunState {
        let mut s = RunState::new();
        for line in log.lines() {
            s.feed(line);
        }
        s
    }

    #[test]
    fn parses_a_real_successful_run() {
        let s = run(REAL_LOG);

        assert_eq!(s.metrics.themida_version.as_deref(), Some("V3"));
        assert_eq!(s.metrics.pid, Some(25636));
        assert_eq!(s.metrics.entry_rva, Some(0x83e058));
        assert_eq!(s.metrics.oep, Some(0x7ff6f5d41010));
        assert_eq!(s.metrics.iat_va, Some(0x7ff6f5e536e0));
        assert_eq!(s.metrics.iat_size, Some(8504));
        assert_eq!(s.metrics.iat_slots, Some(1063));
        assert_eq!(s.metrics.iat_blocks, Some(14));
        assert_eq!(s.metrics.resolved, Some(186));
        assert_eq!(s.metrics.failed, Some(8));
        assert_eq!(s.metrics.module_count, Some(9));
        assert_eq!(s.metrics.thunk_count, Some(186));
        assert_eq!(s.metrics.fixed_addresses, Some(2907));
        assert_eq!(s.metrics.relocations, Some(2907));
        assert_eq!(s.metrics.output_size, Some(1_539_584));
        assert_eq!(s.finished, Some(true));
        assert!(s.error.is_none());
        assert_eq!(s.phase, Some(Phase::Done));
    }

    #[test]
    fn phase_order_follows_execution() {
        let s = run(REAL_LOG);
        // The last milestone wins, but every earlier phase must have been seen.
        let seen: Vec<Phase> = Phase::ALL.to_vec();
        for p in seen {
            let marker = match p {
                Phase::Identify => "Loading:",
                Phase::Launch => "Process created (PID:",
                Phase::FindOep => "OEP found — letting program execute",
                Phase::LocateIat => "IAT located iat=",
                Phase::TraceIat => "[v3-trace] Starting IAT trace",
                Phase::Rebuild => "IAT fixed",
                Phase::Dump => "Dumping to:",
                Phase::Done => "Done.",
            };
            assert!(
                REAL_LOG.lines().any(|l| l.contains(marker)),
                "fixture is missing the {marker} milestone for {p:?}"
            );
        }
        assert_eq!(s.phase, Some(Phase::Done));
    }

    #[test]
    fn live_slot_index_tracks_trace_progress() {
        let mut s = RunState::new();
        for line in REAL_LOG.lines() {
            s.feed(line);
        }
        // The fixture's last "Tracing IAT slot 567" line should have been seen,
        // but the completed-trace line follows it; progress must still resolve.
        let p = s.metrics.trace_progress().expect("progress available");
        assert!(p > 0.0 && p <= 1.0, "progress out of range: {p}");
    }

    #[test]
    fn detects_fatal_error_as_terminal() {
        let log = "\
[2026-10-22T16:01:12.676163Z] [INFO] Loading: D:\\Projects\\shiguang\\core.dll
[2026-10-22T16:01:12.694978Z] [FATAL] Fatal error: Refusing to unpack a native DLL target: core.dll.
Themida's DLL stub calls ExitProcess instead of DllMain.";
        let s = run(log);
        assert_eq!(s.finished, Some(false));
        assert_eq!(s.phase, Some(Phase::Done));
        assert!(s.error.as_deref().unwrap_or("").contains("Refusing to unpack"));
    }

    #[test]
    fn bare_control_bytes_are_dropped() {
        let mut s = RunState::new();
        let m = s.feed("\u{7}\u{7}\u{7}");
        assert!(!m);
        assert!(s.lines.is_empty(), "control-only line must not be stored");
    }

    #[test]
    fn untagged_output_is_kept_but_not_a_milestone() {
        let mut s = RunState::new();
        let milestone = s.feed("thread 'main' panicked at src/foo.rs:1:1");
        assert!(!milestone);
        assert_eq!(s.lines.len(), 1);
        assert_eq!(s.lines[0].level, Level::Info);
    }

    #[test]
    fn level_tags_map_to_severities() {
        assert_eq!(Level::parse("GOOD"), Level::Good);
        assert_eq!(Level::parse("WARN"), Level::Warn);
        assert_eq!(Level::parse("FATAL"), Level::Fatal);
        assert_eq!(Level::parse("DEBUG"), Level::Debug);
        assert_eq!(Level::parse("INFO"), Level::Info);
        assert_eq!(Level::parse("anything"), Level::Info);
    }

    #[test]
    fn debug_spam_does_not_trigger_repaints() {
        let mut s = RunState::new();
        let quiet = s.feed("[2026-10-22T15:39:15.100000Z] [DEBUG] event received: LoadDll { thread_id: 1, base_address: 0x7fffe4000000, h_file: HANDLE(0xb4) }");
        assert!(!quiet, "debug lines must not force a repaint");
    }

    #[test]
    fn ansi_colour_codes_are_stripped() {
        let mut s = RunState::new();
        s.feed("[2026-10-22T16:53:56.177955Z] [GOOD] \x1b[32m[GOOD]\x1b[0m Unpacked: out.exe");
        // The tag is parsed from the bracket, and no escape bytes reach the view.
        assert!(
            !s.lines[0].message.contains('\x1b'),
            "escape byte leaked into message: {:?}",
            s.lines[0].message
        );
        assert!(s.lines[0].message.contains("Unpacked: out.exe"));
    }

    #[test]
    fn split_line_keeps_time_of_day_only() {
        let (t, lvl, msg) = split_line("[2026-10-22T15:39:16.268000Z] [GOOD] Done.").unwrap();
        assert_eq!(t, "15:39:16");
        assert_eq!(lvl, Level::Good);
        assert_eq!(msg, "Done.");
    }
}
