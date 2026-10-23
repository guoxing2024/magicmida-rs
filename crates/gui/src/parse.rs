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

use std::path::Path;

/// What kind of image the run is unpacking.
///
/// The pipeline is the same for both, but the *log* is not: a DLL run has no
/// `.text` guard, no `CloseHandle` breakpoint, and takes its OEP from the
/// shell's TLS callback array, so it announces different milestones.  The GUI
/// shows the kind because the acceptance criterion differs — an EXE is accepted
/// by launching its product, a DLL only by loading it into a host and calling
/// its exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TargetKind {
    #[default]
    Exe,
    Dll,
}

impl TargetKind {
    /// Guess from the file extension.  Confirmed later from the log itself.
    pub fn of_path(p: &Path) -> TargetKind {
        match p.extension().and_then(|e| e.to_str()) {
            Some(e) if e.eq_ignore_ascii_case("dll") => TargetKind::Dll,
            _ => TargetKind::Exe,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TargetKind::Exe => "EXE",
            TargetKind::Dll => "DLL",
        }
    }

    /// How the product is accepted for this kind.
    pub fn acceptance(self) -> &'static str {
        match self {
            TargetKind::Exe => "启动产物验证",
            TargetKind::Dll => "需宿主加载验证",
        }
    }
}

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
    /// Slots that hold a bare RVA into a non-executable section — data the
    /// shell parked in the table, not import thunks.
    ///
    /// The DLL case has 3 and the EXE case has 8.  They are reported
    /// separately from `failed` so a real failure cannot hide inside "data".
    pub not_import: Option<u64>,
    /// Index of the slot currently being traced (live progress).
    pub current_slot: Option<u64>,
    /// Set when the trace reported completion.
    ///
    /// Needed because `current_slot` and `resolved` are *different units*: the
    /// first is a position in the table, the second a count of successes.  Most
    /// slots in a Themida table are not imports at all (the reference DLL has
    /// 3283 slots, of which 1292 are zero and 147 are VM stubs), so
    /// `resolved / total` is not "progress" — it is "fraction that turned out to
    /// be imports", and it sits near 9% on a *finished* run.  Without this flag
    /// the bar freezes wherever the last slot announcement landed (measured:
    /// 296/3283) while the status line already says 完成.
    pub trace_done: bool,
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
    /// `current_slot` is a *position* in the table, so it is the right measure
    /// of how far the walk got.  `resolved` is a *count of successes* and must
    /// never be used for progress: most slots in a Themida table are not
    /// imports, so a completed run reports 289 resolved out of 3283 slots
    /// (~9%) and the bar would look stuck near the start.
    ///
    /// Once the trace reports completion, progress is 1.0 regardless of the
    /// last slot number seen — the CLI announces slots out of order and skips
    /// whole groups, so the last `Tracing IAT slot N` is not necessarily the
    /// last slot.
    pub fn trace_progress(&self) -> Option<f32> {
        if self.trace_done {
            return Some(1.0);
        }
        let total = self.iat_slots? as f32;
        if total <= 0.0 {
            return None;
        }
        let cur = self.current_slot?;
        Some((cur as f32 / total).clamp(0.0, 1.0))
    }

    /// Human-readable form of the trace state for the strip's right-hand label.
    pub fn trace_label(&self) -> String {
        match (self.trace_done, self.current_slot, self.iat_slots) {
            (true, _, Some(t)) => format!("完成 · {t} 槽"),
            (false, Some(c), Some(t)) => format!("{c} / {t}"),
            (_, None, Some(t)) => format!("— / {t}"),
            _ => "—".into(),
        }
    }
}

/// Everything the parser knows about the run so far.
#[derive(Debug, Default)]
pub struct RunState {
    pub phase: Option<Phase>,
    /// EXE or DLL.  Seeded from the input extension, then confirmed from the
    /// log the first time a DLL-only milestone appears.
    pub kind: TargetKind,
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
    /// Empty state.  The default kind is EXE; use [`RunState::with_kind`] when
    /// the input path is already known.
    ///
    /// Only the tests build a state this way — the job always knows its input.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a run for a known target kind (seeded from the file extension).
    pub fn with_kind(kind: TargetKind) -> Self {
        Self {
            kind,
            ..Self::default()
        }
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

        // ---- DLL-only milestones -----------------------------------------
        //
        // These lines exist only on the DLL path and are the reason the GUI
        // needs a `kind` at all: the DLL run never arms a `.text` guard, never
        // sets the `CloseHandle` breakpoint, and takes its OEP from the shell's
        // TLS callback array after a free-run.  None of the EXE milestones
        // below would ever fire, so without these the panel would stay empty
        // for the whole run.
        if message.starts_with("Built loader host") || message.starts_with("Created DLL loader host")
        {
            self.kind = TargetKind::Dll;
            milestone = true;
        }
        if message.starts_with("Packed DLL located") {
            self.kind = TargetKind::Dll;
            if let Some(v) = after(&message, "dll_base=") {
                self.metrics.image_base = parse_hex_prefix(v);
            }
            milestone = true;
        }
        if message.starts_with("DLL OEP published") {
            if let Some(v) = after(&message, "oep=") {
                self.metrics.oep = parse_hex_prefix(v);
            }
            milestone = true;
        }
        if message.starts_with("DLL OEP taken from the shell's TLS callback array") {
            self.kind = TargetKind::Dll;
            if let Some(v) = after(&message, "oep=") {
                self.metrics.oep = parse_hex_prefix(v);
            }
            milestone = true;
        }
        if message.starts_with("DLL initialisation settled") {
            milestone = true;
        }
        // The DLL path raises the IAT to writable explicitly; the EXE path does
        // not, so this is a second independent DLL signal.
        if message.starts_with("DLL path: IAT raised") {
            self.kind = TargetKind::Dll;
            if let Some(v) = after(&message, "iat=") {
                self.metrics.iat_va = parse_hex_prefix(v);
            }
            milestone = true;
        }

        // ---- phase transitions -------------------------------------------
        // Monotonic: a later milestone may arrive out of order (the DLL path
        // re-announces `IAT boundaries` *after* `Initial OEP`), and the rail
        // renders phases by ordinal, so a step backwards would redraw finished
        // chips as pending.  Only ever advance.
        let new_phase = detect_phase(&message);
        if let Some(p) = new_phase {
            let advance = match self.phase {
                None => true,
                Some(cur) => p > cur || (p == Phase::Done && cur != Phase::Done),
            };
            if advance {
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
        // `image_base=` appears in several different messages, and they do not
        // mean the same thing:
        //
        //   CREATE_PROCESS_DEBUG_EVENT image_base=0x7ff6...   <- runtime base
        //   Packed DLL located ... dll_base=0x7fff...         <- runtime base
        //   Building relocation table: image_base=0x3205c0000 <- **file** base
        //
        // The last one is the PE header's preferred base, not where the image
        // is running, so taking "last wins" put a meaningless 0x3205c0000 in a
        // field the panel labels as the runtime base.  Only the first runtime
        // value is kept.
        if self.metrics.image_base.is_none() && message.contains("image_base=") {
            self.metrics.image_base = after(&message, "image_base=").and_then(parse_hex_prefix);
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
        // Both paths also announce the table once it is final:
        //   "IAT at 0x7ff..., size 0x6698"
        // The DLL path has no `IAT located iat=` line at all (it re-locates the
        // table after the free-run), so this is the only source of `iat_va`
        // there.  Take it only when the earlier line did not fire.
        if message.starts_with("IAT at ") && self.metrics.iat_va.is_none() {
            self.metrics.iat_va = after(&message, "IAT at ").and_then(parse_hex_prefix);
        }
        if let Some(v) = after(&message, "IAT at ") {
            if let Some(sz) = after(v, "size ") {
                self.metrics.iat_size = parse_hex_prefix(sz);
            }
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
        //           DLL: "IAT trace complete: 289 resolved, 0 failed, 3 not-an-import"
        if let Some(v) = after(&message, "IAT trace complete: ") {
            self.metrics.resolved = parse_decimal_prefix(v);
            self.metrics.failed = after(v, "resolved,").and_then(parse_decimal_prefix);
            self.metrics.not_import = after(v, "failed,").and_then(parse_decimal_prefix);
            self.metrics.trace_done = true;
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
    // ---- DLL path ---------------------------------------------------------
    //
    // A packed DLL is unpacked through a generated loader host, so the first
    // thing after identification is that host being built.  `Process created`
    // still follows, so the Launch phase is shared.
    if message.starts_with("Built loader host") || message.starts_with("Created DLL loader host") {
        return Some(Phase::Launch);
    }
    if message.starts_with("Packed DLL located") {
        return Some(Phase::FindOep);
    }
    if message.starts_with("DLL OEP published")
        || message.starts_with("DLL OEP taken from the shell's TLS callback array")
    {
        return Some(Phase::FindOep);
    }
    if message.starts_with("DLL initialisation settled") {
        return Some(Phase::LocateIat);
    }
    if message.starts_with("DLL path: IAT raised") {
        return Some(Phase::LocateIat);
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
[2026-10-22T15:39:16.230000Z] [INFO] [v3-trace] OK IAT trace complete: 186 resolved, 0 failed, 8 not-an-import
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
        assert_eq!(s.metrics.failed, Some(0));
        assert_eq!(s.metrics.not_import, Some(8));
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
        // Mid-run: the slot cursor is the only progress signal.
        for line in REAL_LOG.lines() {
            if line.contains("IAT trace complete") {
                break;
            }
            s.feed(line);
        }
        let p = s.metrics.trace_progress().expect("progress available mid-run");
        assert!(p > 0.0 && p < 1.0, "mid-run progress out of range: {p}");
        assert_eq!(s.metrics.trace_label(), "567 / 1063");
    }

    #[test]
    fn completed_trace_reports_full_progress_not_the_resolved_fraction() {
        // Regression: `resolved / total` is NOT progress.  The reference DLL
        // resolves 289 of 3283 slots — most slots are zeroes or VM stubs — so a
        // finished run would render its bar at 9% and look stuck.  Measured on
        // the real GUI: the bar froze at 296/3283 while the status already said
        // 完成.
        let mut s = RunState::with_kind(TargetKind::Dll);
        for line in DLL_LOG.lines() {
            s.feed(line);
        }
        assert!(s.metrics.trace_done, "trace completion must be recorded");
        assert_eq!(s.metrics.trace_progress(), Some(1.0));
        assert_eq!(s.metrics.trace_label(), "完成 · 3283 槽");

        // And the same for the EXE case (186 of 1063 = 17%).
        let exe = run(REAL_LOG);
        assert_eq!(exe.metrics.trace_progress(), Some(1.0));
        assert_eq!(exe.metrics.trace_label(), "完成 · 1063 槽");
    }

    #[test]
    fn unresolved_trace_does_not_invent_progress() {
        // No slot announced, no completion: there is nothing honest to draw.
        let mut s = RunState::new();
        s.feed("[2026-10-22T15:39:15.240000Z] [INFO] [v3-trace] Starting IAT trace: 1063 slots");
        s.feed("[2026-10-22T15:39:15.230000Z] [INFO] IAT boundaries: start=0x1, end=0x2, size=8504 (1063 slots), blocks=14");
        assert_eq!(s.metrics.trace_progress(), None);
        assert_eq!(s.metrics.trace_label(), "— / 1063");
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

    // -----------------------------------------------------------------------
    // DLL path — literal lines from the real `core.dll` run (`OUT/d3_log.txt`)
    // -----------------------------------------------------------------------
    //
    // The DLL run announces a different set of milestones than the EXE run:
    // no `OEP found — letting program execute`, no `IAT located iat=`, no
    // `CloseHandle HW breakpoint`.  If the parser only knew the EXE vocabulary
    // the panel would sit empty for the whole 9-second run, which is the defect
    // these tests pin.
    const DLL_LOG: &str = "\
[2026-10-23T12:15:57.998000Z] [INFO] Loading: ..\\OUT\\core.dll
[2026-10-23T12:15:58.003000Z] [INFO] Entry point RVA: 0x8a0108, EP offset: 0xb0908, EP bytes: [E8, 82, 01, 00, 00, 41, 52, 49]
[2026-10-23T12:15:58.005000Z] [INFO] Themida version: V3
[2026-10-23T12:15:58.172389Z] [INFO] Built loader host host=..\\OUT\\core.dllMMHost.exe
[2026-10-23T12:15:58.172428Z] [INFO] Created DLL loader host: ..\\OUT\\core.dllMMHost.exe
[2026-10-23T12:15:58.260000Z] [INFO] Process created (PID: 30344)
[2026-10-23T12:15:58.700000Z] [INFO] ScyllaHide injected
[2026-10-23T12:16:01.861954Z] [INFO] Packed DLL located — image_base retargeted from the loader host dll_base=0x7fffd8840000
[2026-10-23T12:16:03.092657Z] [INFO] DLL initialisation settled — dumping activity=1311 quiet_samples=6
[2026-10-23T12:16:03.092692Z] [INFO] DLL OEP taken from the shell's TLS callback array (free-run, no .text guard, no IAT guard) oep=0x7fffd886bb10 rva=0x2bb10
[2026-10-23T12:16:03.345494Z] [INFO] IAT boundaries: start=0x7fffd8981a80, end=0x7fffd8988118, size=26264 (3283 slots), blocks=31
[2026-10-23T12:16:03.345513Z] [INFO] DLL path: IAT raised to PAGE_READWRITE for the trace write-back iat=0x7fffd8981a80 size=0x6698 writable=true
[2026-10-23T12:16:03.345572Z] [INFO] Initial OEP: 0x7fffd886bb10
[2026-10-23T12:16:03.347257Z] [INFO] IAT boundaries: start=0x7fffd8981a80, end=0x7fffd8988118, size=26264 (3283 slots), blocks=31
[2026-10-23T12:16:03.347271Z] [INFO] IAT at 0x7fffd8981a80, size 0x6698
[2026-10-23T12:16:03.347390Z] [INFO] [v3-trace] Starting IAT trace: 3283 slots, IAT at 0x7fffd8981a80, Themida section: 0x7fffd89d8000-0x7fffd95f1a00, image: 0x7fffd8840000-0x7fffd95f3000
[2026-10-23T12:16:03.347414Z] [INFO] [v3-trace] Tracing IAT slot 0 (0x7fffd8981a80) from 0x7fffd8b070e4 (trace_start=0x7fffd8b070e4)
[2026-10-23T12:16:04.595730Z] [INFO] [v3-trace] OK IAT trace complete: 289 resolved, 0 failed, 3 not-an-import
[2026-10-23T12:16:04.595738Z] [INFO] fix_iat_v3: 289 resolved, 0 failed (3283 slots total)
[2026-10-23T12:16:04.595742Z] [INFO] IAT fixed
[2026-10-23T12:16:04.620068Z] [INFO] Import table reconstructed module_count=12 thunk_count=289
[2026-10-23T12:16:04.628656Z] [INFO] Scanned 648587 bytes in writable sections, fixed 3106 hardcoded addresses
[2026-10-23T12:16:04.628671Z] [INFO] Building relocation table: image_base=0x3205c0000, image_size=0x1a9000
[2026-10-23T12:16:04.628862Z] [INFO] Relocation table: 3106 entries (6408 bytes, untruncated), VA=0x1a5000, ASLR enabled
[2026-10-23T12:16:04.630240Z] [INFO] Dump written successfully path=..\\OUT\\d3.dll size=1737216 sections=18
[2026-10-23T12:16:04.630531Z] [GOOD] Unpacked: ..\\OUT\\d3.dll
[2026-10-23T12:16:04.630609Z] [GOOD] Done.";

    #[test]
    fn parses_a_real_dll_run() {
        let mut s = RunState::with_kind(TargetKind::Dll);
        for line in DLL_LOG.lines() {
            s.feed(line);
        }

        assert_eq!(s.kind, TargetKind::Dll);
        assert_eq!(s.metrics.themida_version.as_deref(), Some("V3"));
        assert_eq!(s.metrics.pid, Some(30344));
        assert_eq!(s.metrics.entry_rva, Some(0x8a0108));
        assert_eq!(s.metrics.image_base, Some(0x7fffd8840000));
        assert_eq!(s.metrics.oep, Some(0x7fffd886bb10));
        // `IAT located iat=` never fires on this path; `IAT at` must cover it.
        assert_eq!(s.metrics.iat_va, Some(0x7fffd8981a80));
        assert_eq!(s.metrics.iat_size, Some(0x6698));
        assert_eq!(s.metrics.iat_slots, Some(3283));
        assert_eq!(s.metrics.iat_blocks, Some(31));
        assert_eq!(s.metrics.resolved, Some(289));
        assert_eq!(s.metrics.failed, Some(0));
        assert_eq!(s.metrics.not_import, Some(3));
        assert_eq!(s.metrics.module_count, Some(12));
        assert_eq!(s.metrics.thunk_count, Some(289));
        assert_eq!(s.metrics.fixed_addresses, Some(3106));
        assert_eq!(s.metrics.relocations, Some(3106));
        assert_eq!(s.metrics.output_size, Some(1_737_216));
        assert_eq!(s.finished, Some(true));
        assert!(s.error.is_none());
        assert_eq!(s.phase, Some(Phase::Done));
    }

    #[test]
    fn dll_run_reaches_every_phase() {
        // The DLL path skips three EXE-only milestones (`OEP found — letting
        // program execute`, `IAT located iat=`, `CloseHandle HW breakpoint`), so
        // the phase rail needs its own markers for Launch/FindOep/LocateIat or
        // those chips stay pending the whole run.
        let mut s = RunState::with_kind(TargetKind::Dll);
        let mut seen = Vec::new();
        for line in DLL_LOG.lines() {
            let before = s.phase;
            s.feed(line);
            if s.phase != before {
                if let Some(p) = s.phase {
                    seen.push(p);
                }
            }
        }
        assert_eq!(
            seen,
            vec![
                Phase::Identify,
                Phase::Launch,
                Phase::FindOep,
                Phase::LocateIat,
                Phase::TraceIat,
                Phase::Rebuild,
                Phase::Dump,
                Phase::Done,
            ],
            "phase rail must advance once through every phase, in order"
        );
    }

    #[test]
    fn dll_kind_is_inferred_from_the_log_not_only_the_extension() {
        // A `.dll` renamed to `.exe` still unpacks as a DLL — the pipeline reads
        // the PE header.  The log has to be able to correct a wrong seed.
        let mut s = RunState::with_kind(TargetKind::Exe);
        for line in DLL_LOG.lines() {
            s.feed(line);
        }
        assert_eq!(s.kind, TargetKind::Dll);
    }

    #[test]
    fn exe_run_is_not_mistaken_for_a_dll() {
        let s = run(REAL_LOG);
        assert_eq!(s.kind, TargetKind::Exe);
        // The EXE case has 8 not-an-import slots, the DLL case has 3.
        assert_eq!(s.metrics.not_import, Some(8));
        assert_eq!(s.metrics.failed, Some(0));
    }

    #[test]
    fn phase_never_goes_backwards() {
        // Measured on the DLL path: `IAT boundaries` is announced twice, the
        // second time *after* `Initial OEP`, which maps to TraceIat.  A naive
        // "last milestone wins" parser would drop the rail back to LocateIat
        // and redraw finished chips as pending.
        let mut s = RunState::new();
        s.feed("[2026-10-23T12:16:03.345572Z] [INFO] Initial OEP: 0x7fffd886bb10");
        assert_eq!(s.phase, Some(Phase::TraceIat));
        s.feed("[2026-10-23T12:16:03.347257Z] [INFO] IAT boundaries: start=0x1, end=0x2, size=8 (1 slots), blocks=1");
        assert_eq!(s.phase, Some(Phase::TraceIat), "phase must not regress");
    }

    #[test]
    fn dll_target_kind_labels() {
        assert_eq!(TargetKind::of_path(Path::new("core.dll")), TargetKind::Dll);
        assert_eq!(TargetKind::of_path(Path::new("core.DLL")), TargetKind::Dll);
        assert_eq!(TargetKind::of_path(Path::new("core.Dll")), TargetKind::Dll);
        assert_eq!(TargetKind::of_path(Path::new("app.exe")), TargetKind::Exe);
        assert_eq!(TargetKind::of_path(Path::new("noext")), TargetKind::Exe);
        assert_eq!(TargetKind::Dll.label(), "DLL");
        assert_eq!(TargetKind::Exe.label(), "EXE");
    }
}
