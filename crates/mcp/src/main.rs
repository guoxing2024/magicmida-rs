//! Magicmida-RS MCP server — exposes the Themida unpacker to AI clients.
//!
//! # Why the tools are shaped this way
//!
//! An MCP `tools/call` is request/response, and DSH's default per-call timeout
//! is **60 s** (`toolCallTimeoutMs`, see `dsh-mcp-client`'s README).  But an
//! unpack run is not a 60-second operation:
//!
//! | case | measured |
//! |---|---|
//! | x86 sample, success | 5.5 s |
//! | x64 sample, success | ~27 s |
//! | x64 sample, failure path | **466 s** |
//!
//! and the debug loop's `wait_event()` has **no timeout** at all, so a run can
//! in principle wait forever.
//!
//! A single blocking `unpack` tool would therefore time out client-side on
//! exactly the runs that matter most — the long, failing ones — and the model
//! would never see the diagnosis.  So the pipeline is split into a job model:
//!
//! ```text
//! unpack_start  -> { job_id }            returns immediately
//! unpack_status -> { phase, metrics, ... } poll until done
//! unpack_cancel -> { }                   kills the CLI *and its tree*
//! verify        -> { ... }               synchronous; pure file comparison
//! triage        -> { ... }               synchronous; PE header facts
//! ```
//!
//! `unpack_status` doubles as the long-poll: it waits up to `wait_ms` (bounded
//! well below the client timeout) so a normal 5–30 s run usually finishes inside
//! one or two calls instead of dozens of polls.
//!
//! # Transport
//!
//! Newline-delimited JSON-RPC 2.0 on stdin/stdout, which is what `stdio` MCP
//! clients (including DSH's `dsh-mcp-client`) speak.  Nothing is written to
//! stdout except protocol messages — all logging goes to stderr.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use mida_packer_api::{Evidence, VmProtectMode};
use serde_json::{json, Value};

use mida_run::{kill_tree, Job, Phase, RunReport, RunState};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Protocol revisions this server can speak, newest first.
///
/// # Why a list and not one constant
///
/// MCP `initialize` is a *negotiation*: the client sends the revision it wants,
/// and the server answers with the revision it will use.  An earlier version of
/// this server replied with a single hard-coded string, which broke every real
/// client:
///
/// Measured 2026-10-24 against DSH's bundled SDK
/// (`@modelcontextprotocol/client` 2.2.0, via `dsh-mcp-client`):
///
/// ```text
/// SUPPORTED: ["2025-11-25","2025-06-18","2025-03-26","2024-11-05","2024-10-07"]
/// server replied 2026-07-28  ->  "Server's protocol version is not supported"
/// ```
///
/// The client rejects a version it does not know, so the handshake fails and the
/// tools never appear — even though the server is otherwise correct.  The
/// constant had been *assumed* rather than measured; it is not a version any
/// shipped SDK recognises.
///
/// So: echo the client's revision when it is one we implement, else answer with
/// our newest supported one.  That is what the specification asks for, and it
/// keeps working as clients move forward.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
];

/// The revision used when the client asks for one we do not implement.
///
/// Newest-first ordering above means this is the first entry; keeping it a
/// named constant makes the intent explicit at the call site.
const PREFERRED_PROTOCOL_VERSION: &str = SUPPORTED_PROTOCOL_VERSIONS[0];

/// Pick the revision to answer with.
///
/// Returns the client's own revision when we implement it (the spec's
/// negotiation), otherwise [`PREFERRED_PROTOCOL_VERSION`].  A client that sends
/// no revision at all gets the preferred one.
fn negotiate_protocol_version(params: &Value) -> &'static str {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    match requested {
        Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => {
            // The caller's string is not 'static, so map it back to the static
            // entry.  `contains` above guarantees the lookup succeeds.
            SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .copied()
                .find(|s| *s == v)
                .unwrap_or(PREFERRED_PROTOCOL_VERSION)
        }
        _ => PREFERRED_PROTOCOL_VERSION,
    }
}

/// Long-poll ceiling for `unpack_status`.
///
/// Deliberately far below the client's 60 s `toolCallTimeoutMs`: the server must
/// answer *before* the client gives up, or the call looks like a hang and the
/// model retries into a second concurrent run.  45 s leaves room for the
/// response to be serialised and delivered.
const MAX_WAIT_MS: u64 = 45_000;

/// Default long-poll when the caller does not ask for one.
///
/// Non-zero on purpose: a successful run is 5–30 s, so waiting turns "poll
/// until done" into one or two calls.  A caller that wants a pure snapshot can
/// pass `wait_ms: 0`.
const DEFAULT_WAIT_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// Job registry
// ---------------------------------------------------------------------------

/// One unpack run owned by the server.
struct JobHandle {
    /// Shared with the pump thread; this is the parsed run state.
    state: Arc<Mutex<RunState>>,
    /// PID of the `mida-cli` child, for cancellation.
    cli_pid: u32,
    /// Set by the pump thread when the child exits.
    exit_code: Arc<Mutex<Option<i32>>>,
    /// When the run started, for the elapsed-time report.
    started_at: std::time::Instant,
    /// The target being unpacked, echoed back in status.
    input: PathBuf,
    /// The product path we asked for.
    output: PathBuf,
}

impl JobHandle {
    fn finished(&self) -> Option<i32> {
        *self.exit_code.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn report(&self) -> Option<RunReport> {
        let code = self.finished()?;
        let elapsed = self.started_at.elapsed().as_millis() as u64;
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Some(RunReport::from_state(&state, code, elapsed))
    }

    /// A live snapshot for `unpack_status`, even mid-run.
    ///
    /// # Lock ordering — this used to deadlock
    ///
    /// An earlier version held the `state` lock for the whole body *and* called
    /// `self.report()` inside the `json!` literal, which locks `state` again.
    /// `std::sync::Mutex` is not reentrant, so the server hung forever the first
    /// time a run finished — measured: `unpack_status` never answered, the
    /// client timed out at 150 s, and the process had to be killed.
    ///
    /// The fix is structural: take every value this function needs *while*
    /// holding the lock, drop it, and only then build the JSON.  `report()` is
    /// called with no lock held.
    fn snapshot(&self) -> Value {
        let done = self.finished();
        let elapsed = self.started_at.elapsed().as_millis() as u64;
        let report_ok = self.report().map(|r| r.ok);

        let (phase, kind, output_path, error, metrics) = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            (
                state.phase.map(phase_name),
                state.kind.label(),
                state.output_path.clone(),
                state.error.clone(),
                metrics_json(&state),
            )
        };

        json!({
            "job_id": Value::Null, // filled by the caller
            "done": done.is_some(),
            "exit_code": done,
            "ok": report_ok,
            "phase": phase,
            "kind": kind,
            "input": self.input.display().to_string(),
            "output_requested": self.output.display().to_string(),
            "output_path": output_path,
            "error": error,
            "elapsed_ms": elapsed,
            "metrics": metrics,
        })
    }
}

fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::Identify => "identify",
        Phase::Launch => "launch",
        Phase::FindOep => "find_oep",
        Phase::LocateIat => "locate_iat",
        Phase::TraceIat => "trace_iat",
        Phase::Rebuild => "rebuild",
        Phase::Dump => "dump",
        Phase::Done => "done",
    }
}

fn metrics_json(state: &RunState) -> Value {
    let m = &state.metrics;
    let hex = |v: Option<u64>| v.map(|x| format!("{x:#x}"));
    json!({
        "themida_version": m.themida_version,
        "debuggee_pid": m.pid,
        "entry_rva": hex(m.entry_rva),
        "image_base": hex(m.image_base),
        "oep": hex(m.oep),
        "iat_va": hex(m.iat_va),
        "iat_size": hex(m.iat_size),
        "iat_slots": m.iat_slots,
        "iat_blocks": m.iat_blocks,
        "resolved": m.resolved,
        "failed": m.failed,
        "not_an_import": m.not_import,
        "trace_done": m.trace_done,
        "module_count": m.module_count,
        "thunk_count": m.thunk_count,
        "fixed_addresses": m.fixed_addresses,
        "relocations": m.relocations,
        "output_size": m.output_size,
    })
}

/// Server-wide state.
struct Server {
    /// The CLI for x64 targets.
    cli_x64: PathBuf,
    /// The CLI for x86 targets, when one was found.
    ///
    /// The unpacker is architecture-specific: the CLI drives a debugger whose
    /// register layout matches the debuggee, so a 64-bit `mida-cli` refuses a
    /// 32-bit target with
    /// `File is for the wrong architecture (Machine=IMAGE_FILE_MACHINE(332)):
    /// expected 64-bit, please use the 32-bit version of Magicmida`.
    ///
    /// Measured: the MCP server, handed the x86 reference sample while
    /// configured only with the x64 CLI, produced exactly that error.  The
    /// diagnosis was correct and the plumbing was not — so the server now picks
    /// the CLI from the target's own PE header.
    cli_x86: Option<PathBuf>,
    jobs: Mutex<HashMap<String, Arc<JobHandle>>>,
    next_id: AtomicU64,
}

impl Server {
    fn new(cli_x64: PathBuf, cli_x86: Option<PathBuf>) -> Self {
        Self {
            cli_x64,
            cli_x86,
            jobs: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Choose the CLI that matches the target's architecture.
    ///
    /// Returns a clear error rather than letting the CLI fail later with its
    /// own message, because the CLI's message is about the *CLI* being the
    /// wrong build, which reads like a tool bug rather than a missing install.
    fn cli_for(&self, input: &Path) -> Result<&PathBuf> {
        let pe = mida_pe::PeHeader::from_file(input)
            .map_err(|e| anyhow!("cannot parse {}: {e}", input.display()))?;
        if pe.is_64bit {
            return Ok(&self.cli_x64);
        }
        match &self.cli_x86 {
            Some(p) => Ok(p),
            None => Err(anyhow!(
                "{} is a 32-bit (x86) target, which needs the i686 build of mida-cli. \
                 Build it with `cargo build --release --target i686-pc-windows-gnu` and \
                 place it next to mida-mcp.exe as `mida-cli-x86.exe`, or set MIDA_CLI_X86.",
                input.display()
            )),
        }
    }

    fn new_job_id(&self) -> String {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("job{n}")
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

/// `unpack_start` — spawn `mida-cli /unpack` and return a job id at once.
fn tool_unpack_start(server: &Server, args: &Value) -> Result<Value> {
    let input = args
        .get("input")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`input` is required (path to the packed binary)"))?;
    let input = PathBuf::from(input);

    if !input.is_file() {
        return Err(anyhow!(
            "input not found or not a file: {}",
            input.display()
        ));
    }

    // The CLI derives `<stem>U.<ext>` when no output is given; compute the same
    // path so `unpack_status` can report it before the run finishes.
    let output = match args.get("output").and_then(Value::as_str) {
        Some(o) => PathBuf::from(o),
        None => default_output_path(&input),
    };
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow!("cannot create output directory {}: {e}", parent.display())
            })?;
        }
    }

    let verbose = args.get("verbose").and_then(Value::as_bool).unwrap_or(false);

    // Pick the CLI whose architecture matches the target.  Doing this here
    // means the caller gets a precise error instead of the CLI's own
    // "wrong architecture" message, which reads like a tool defect.
    let cli = server.cli_for(&input)?.clone();

    let mut job = Job::spawn(&cli, &input, &output, verbose).map_err(|e| {
        anyhow!(
            "failed to spawn {}: {e}",
            cli.display()
        )
    })?;

    let cli_pid = job.cli_pid();
    let state = Arc::clone(&job.state);
    let exit_code: Arc<Mutex<Option<i32>>> = Arc::new(Mutex::new(None));

    // Pump thread: drains the child's output into the parser and records the
    // exit code.  This is what makes the tool non-blocking — the caller polls
    // the shared state instead of waiting on a pipe.
    let pump_state = Arc::clone(&state);
    let pump_exit = Arc::clone(&exit_code);
    std::thread::spawn(move || loop {
        let (_dirty, exit) = job.pump();
        if let Some(code) = exit {
            *pump_exit.lock().unwrap_or_else(|e| e.into_inner()) = Some(code);
            // Drain anything still buffered so the final `Done.`/`[FATAL]`
            // line is parsed before we report finished.
            for _ in 0..50 {
                let (_, again) = job.pump();
                if again.is_none() {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            let _ = &pump_state;
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
    });

    let job_id = server.new_job_id();
    let handle = Arc::new(JobHandle {
        state,
        cli_pid,
        exit_code,
        started_at: std::time::Instant::now(),
        input: input.clone(),
        output: output.clone(),
    });
    server
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(job_id.clone(), handle);

    Ok(json!({
        "job_id": job_id,
        "cli_pid": cli_pid,
        "input": input.display().to_string(),
        "output_requested": output.display().to_string(),
        "note": "Poll with unpack_status. A typical run is 5-30 s; the failure \
                 path on some samples can take minutes.",
    }))
}

/// The CLI's own `<stem>U.<ext>` convention, computed here so status can report
/// the intended product before the run finishes.
fn default_output_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("exe");
    let name = format!("{stem}U.{ext}");
    input.parent().unwrap_or(Path::new(".")).join(name)
}

/// `unpack_status` — snapshot, optionally long-polling until done.
fn tool_unpack_status(server: &Server, args: &Value) -> Result<Value> {
    let job_id = args
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`job_id` is required"))?;

    let handle = server
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(job_id)
        .cloned()
        .ok_or_else(|| anyhow!("unknown job_id: {job_id}"))?;

    let wait_ms = args
        .get("wait_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_WAIT_MS)
        .min(MAX_WAIT_MS);

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
    while handle.finished().is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    let mut snap = handle.snapshot();
    if let Value::Object(ref mut map) = snap {
        map.insert("job_id".into(), json!(job_id));
    }

    // When the run has finished, attach the full report (summary + bounded log
    // tail) so a caller that stopped polling here needs nothing else.
    if let Some(report) = handle.report() {
        if let Value::Object(ref mut map) = snap {
            map.insert("summary".into(), json!(report.summary()));
            map.insert(
                "log_tail".into(),
                json!(report
                    .log_tail
                    .iter()
                    .map(|l| format!("[{}] {}", level_name(l.level), l.message))
                    .collect::<Vec<_>>()),
            );
        }
    }
    Ok(snap)
}

fn level_name(l: mida_run::Level) -> &'static str {
    use mida_run::Level;
    match l {
        Level::Info => "INFO",
        Level::Good => "GOOD",
        Level::Warn => "WARN",
        Level::Fatal => "FATAL",
        Level::Debug => "DEBUG",
    }
}

/// `unpack_cancel` — kill the CLI and its whole process tree.
fn tool_unpack_cancel(server: &Server, args: &Value) -> Result<Value> {
    let job_id = args
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`job_id` is required"))?;
    let handle = server
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(job_id)
        .cloned()
        .ok_or_else(|| anyhow!("unknown job_id: {job_id}"))?;

    let already = handle.finished();
    if already.is_none() {
        // `/T` so the debuggee and any generated loader host go with it.
        // Killing only the CLI would leave the debuggee running and the CLI
        // would never notice.
        kill_tree(handle.cli_pid);
    }
    Ok(json!({
        "job_id": job_id,
        "cancelled": already.is_none(),
        "already_finished_with": already,
    }))
}

/// `verify` — compare a product against a reference.  Pure file work, so it is
/// synchronous and fast (milliseconds).
fn tool_verify(args: &Value) -> Result<Value> {
    let unpacked = args
        .get("unpacked")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`unpacked` is required"))?;
    let reference = args
        .get("reference")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`reference` is required"))?;

    let a = mida_pe::PeHeader::from_file(Path::new(unpacked))
        .map_err(|e| anyhow!("cannot parse {unpacked}: {e}"))?;
    let b = mida_pe::PeHeader::from_file(Path::new(reference))
        .map_err(|e| anyhow!("cannot parse {reference}: {e}"))?;

    let size_of = |p: &str| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);

    let sections: Vec<Value> = a
        .sections
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let peer = b.sections.get(i);
            json!({
                "index": i,
                "name": s.name,
                "va": format!("{:#x}", s.virtual_address),
                "virtual_size": format!("{:#x}", s.virtual_size),
                "matches_reference": peer.map(|p| {
                    p.name == s.name
                        && p.virtual_size == s.virtual_size
                        && p.characteristics == s.characteristics
                }),
            })
        })
        .collect();

    Ok(json!({
        "architecture_matches": a.is_64bit == b.is_64bit,
        "architecture": if a.is_64bit { "x64" } else { "x86" },
        "entry_point": format!("{:#x}", a.entry_point),
        "entry_point_matches": a.entry_point == b.entry_point,
        "section_count": a.sections.len(),
        "reference_section_count": b.sections.len(),
        "sections": sections,
        "size": size_of(unpacked),
        "reference_size": size_of(reference),
    }))
}

/// `triage` — PE facts plus a packer verdict, without running anything.  Useful
/// as the first call: it answers "which packer, which VMProtect mode, which
/// architecture path?" cheaply, and carries the evidence behind the verdict so a
/// surprising answer is diagnosable rather than a bare boolean.
fn tool_triage(args: &Value) -> Result<Value> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`path` is required"))?;
    // Read once and parse from the bytes: the VMProtect detector inspects
    // section *contents* (runtime section, scrambled `.pdata`), not just
    // headers, so the file has to be in memory.
    let image = std::fs::read(Path::new(path)).map_err(|e| anyhow!("cannot read {path}: {e}"))?;
    let pe = mida_pe::PeHeader::from_bytes(&image)
        .map_err(|e| anyhow!("cannot parse {path}: {e}"))?;
    Ok(triage_report(&pe, &image))
}

/// Build the triage report for an already-parsed image.
///
/// Split from [`tool_triage`] so the classification can be tested against
/// synthesised headers instead of files on disk.
fn triage_report(pe: &mida_pe::PeHeader, image: &[u8]) -> Value {
    let sections: Vec<Value> = pe
        .sections
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "va": format!("{:#x}", s.virtual_address),
                "virtual_size": format!("{:#x}", s.virtual_size),
                "raw_size": format!("{:#x}", s.raw_size),
                "characteristics": format!("{:#x}", s.characteristics),
                "executable": s.characteristics & 0x2000_0000 != 0,
                "writable": s.characteristics & 0x8000_0000 != 0,
            })
        })
        .collect();

    // The Themida markers this project keys on.  Reported here (and folded into
    // the `packer` verdict below) so an agent can decide whether `/unpack` is
    // worth attempting before paying for a run.
    let has_winlice = pe.sections.iter().any(|s| s.name.contains(".winlice"));
    let has_boot = pe.sections.iter().any(|s| s.name.contains(".boot"));
    let has_themida = pe.sections.iter().any(|s| s.name.contains(".themida"));
    let unnamed_exec_write = pe.sections.iter().any(|s| {
        s.name.is_empty()
            && s.characteristics & 0x2000_0000 != 0
            && s.characteristics & 0x8000_0000 != 0
    });
    let likely_themida = has_winlice || has_boot || has_themida || unnamed_exec_write;

    // The packer gate, in the same order as `/analyze`: VMProtect's structured
    // detection first, then UPX's, Themida's markers only when neither says
    // yes.  The order is load-bearing — measured over 87 samples, Themida's
    // `is_themida_section` shape also fires on a VMProtect `Packed` target AND
    // on UPX's `UPX0` section, so the reverse order would mislabel both (see
    // `mida-packer-api`'s crate docs and the upx crate's gate).
    let vmprotect = mida_packers_vmprotect::detect(pe, image);
    let upx = if vmprotect.is_none() {
        mida_packers_upx::detect(pe, image)
    } else {
        None
    };

    let packer = if let Some(d) = &vmprotect {
        json!({
            "family": d.family().label(),
            "mode": d.kind.vmprotect_mode().map(|m| m.label()),
            "summary": d.summary(),
            "evidence": evidence_list(&d.evidence),
            "absent": evidence_list(&d.absent),
        })
    } else if let Some(d) = &upx {
        json!({
            "family": d.family().label(),
            "mode": Value::Null,
            "summary": d.summary(),
            "evidence": evidence_list(&d.evidence),
            "absent": evidence_list(&d.absent),
        })
    } else if likely_themida {
        let mut ev: Vec<Value> = Vec::new();
        if has_winlice {
            ev.push(json!({
                "code": "winlice-section",
                "detail": "section `.winlice` present",
            }));
        }
        if has_boot {
            ev.push(json!({
                "code": "boot-section",
                "detail": "section `.boot` present",
            }));
        }
        if has_themida {
            ev.push(json!({
                "code": "themida-section",
                "detail": "section `.themida` present",
            }));
        }
        if unnamed_exec_write {
            ev.push(json!({
                "code": "unnamed-exec-write-section",
                "detail": "an unnamed section is executable and writable",
            }));
        }
        json!({
            "family": "Themida",
            "mode": Value::Null,
            "summary": "Themida",
            "evidence": ev,
            "absent": [],
        })
    } else {
        json!({
            "family": "unknown",
            "mode": Value::Null,
            "summary": "no recognised packer",
            "evidence": [],
            "absent": [],
        })
    };

    // The hint names the pipeline that can actually produce a product for this
    // verdict — the whole point of classifying in triage.
    let hint = if let Some(d) = &vmprotect {
        match d.kind.vmprotect_mode() {
            Some(VmProtectMode::Packed) => {
                "Packed: the code is not in the file. Run the target, then use /dump-image \
                 <pid> <out> --wait; the carved payload decodes to a runnable PE (README: \
                 'Worked example'). unpack_start is Themida-only and will refuse."
            }
            Some(VmProtectMode::MinProtection) => {
                "MinProtection: the code is in the file. /analyze <file> [--extract <dir>] \
                 reports the structure and extracts payloads with no desktop session."
            }
            None => "VMProtect: unpack_start is Themida-only and will refuse.",
        }
    } else if upx.is_some() {
        "UPX: the whole original image is one statically-decodable stream in the file, 
         so no desktop session is involved at all. The CLI's /unpack <file> --packer upx 
         restores the original statically (byte-identical to upx -d); /analyze <file> 
         reports the layout. unpack_start is Themida-only and will refuse."
    } else if likely_themida {
        if pe.is_64bit {
            "Themida x64: verified path (golden record exists). unpack_start + \
             unpack_status; needs an interactive desktop session."
        } else {
            "Themida x86: verified end to end (needs mida-cli-x86.exe beside \
             mida-mcp.exe); same desktop-session requirement."
        }
    } else {
        "No recognised packer: this build classifies Themida, VMProtect and UPX. \
         There is nothing here for unpack_start."
    };

    json!({
        "architecture": if pe.is_64bit { "x64" } else { "x86" },
        "image_base": format!("{:#x}", pe.image_base),
        "entry_point_rva": format!("{:#x}", pe.entry_point),
        "size_of_image": format!("{:#x}", pe.size_of_image()),
        "sections": sections,
        // The verdict, with the evidence that produced it.
        "packer": packer,
        // Kept verbatim for callers of the first version of this tool.
        "themida_markers": {
            "winlice": has_winlice,
            "boot": has_boot,
            "themida": has_themida,
            "unnamed_exec_write": unnamed_exec_write,
        },
        "likely_themida": likely_themida,
        "hint": hint,
    })
}

/// Render evidence as `[{code, detail}]`, the shape the rest of the report uses.
fn evidence_list(list: &[Evidence]) -> Vec<Value> {
    list.iter()
        .map(|e| json!({ "code": e.code, "detail": e.detail }))
        .collect()
}

// ---------------------------------------------------------------------------
// Tool catalogue
// ---------------------------------------------------------------------------

fn tool_definitions() -> Value {
    json!([
        {
            "name": "triage",
            "description": "Report PE facts and classify the packer without running anything: \
                            family (Themida / VMProtect / UPX / unknown), the VMProtect mode \
                            (min-protection or packed) when VMProtect, and the evidence behind \
                            the verdict. Call this first to pick the pipeline and the \
                            architecture path.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path to the PE file." }
                },
                "required": ["path"]
            }
        },
        {
            "name": "unpack_start",
            "description": "Start unpacking a Themida-protected binary. Returns a job_id immediately; \
                            the run continues in the background. Poll with unpack_status.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "input": { "type": "string", "description": "Absolute path to the packed binary." },
                    "output": { "type": "string", "description": "Optional product path. Defaults to <stem>U.<ext> next to the input." },
                    "verbose": { "type": "boolean", "description": "Enable the CLI's debug log stream." }
                },
                "required": ["input"]
            }
        },
        {
            "name": "unpack_status",
            "description": "Snapshot a running or finished job. Long-polls up to wait_ms (default 30000, max 45000) \
                            so a normal 5-30 s run usually completes within one call. When the job is done the result \
                            includes a summary, the extracted metrics and a bounded log tail.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": { "type": "string", "description": "Id returned by unpack_start." },
                    "wait_ms": { "type": "integer", "description": "Long-poll budget in ms. 0 returns immediately." }
                },
                "required": ["job_id"]
            }
        },
        {
            "name": "unpack_cancel",
            "description": "Cancel a run. Kills the CLI and its whole process tree, including the debuggee.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": { "type": "string", "description": "Id returned by unpack_start." }
                },
                "required": ["job_id"]
            }
        },
        {
            "name": "verify",
            "description": "Compare an unpacked product against a reference binary: architecture, entry point, \
                            section count and per-section header agreement. Synchronous and fast.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "unpacked": { "type": "string", "description": "Path to the product." },
                    "reference": { "type": "string", "description": "Path to the known-good reference." }
                },
                "required": ["unpacked", "reference"]
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// Transport decoding
// ---------------------------------------------------------------------------

/// Decode one protocol line.
///
/// # Why this is not just `String::from_utf8`
///
/// The MCP stdio transport is defined as UTF-8, and the server must accept
/// that.  But on Windows the *client* is frequently a PowerShell script or a
/// .NET host, and `ProcessStartInfo.StandardInputEncoding` defaults to the
/// console code page — GB2312 on a zh-CN machine.  Measured 2026-10-24: a
/// `triage` call carrying `D:\Projects\shiguang\时光一键宏.exe` arrived as GBK
/// bytes, `read_line` returned `InvalidData`, and the `?` in `main` killed the
/// server outright.  The client saw a dead pipe and no diagnosis.
///
/// Two lessons, both implemented here:
///
/// 1. A malformed line must never terminate the server.  Any protocol peer can
///    send garbage; dropping the connection turns a recoverable client bug into
///    a crash with no error message.
/// 2. UTF-8 first (that is the spec), then the system ANSI code page as a
///    fallback.  A Windows client that forgot to set its encoding then still
///    works instead of silently addressing a file whose name is mojibake.
///
/// Returns the text plus the encoding that produced it, so the log can say
/// which path was taken.
fn decode_line(bytes: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), "utf-8"),
        Err(_) => match ansi::decode(ansi::CP_ACP, bytes) {
            Some(s) => (s, "ansi"),
            // Neither UTF-8 nor the ANSI code page: keep going with replacement
            // characters.  The JSON will fail to parse and the caller gets a
            // warning, which is the correct outcome — but the server lives.
            None => (String::from_utf8_lossy(bytes).into_owned(), "lossy"),
        },
    }
}

/// Minimal `MultiByteToWideChar` binding.
///
/// Deliberately hand-rolled rather than pulling in the `windows` crate: this is
/// one function, used on one error path, and the MCP server's dependency set is
/// kept small on purpose.
#[cfg(windows)]
mod ansi {
    /// `CP_ACP` — the system default ANSI code page.
    pub const CP_ACP: u32 = 0;

    #[link(name = "kernel32")]
    extern "system" {
        fn MultiByteToWideChar(
            code_page: u32,
            flags: u32,
            multi_byte_str: *const u8,
            cb_multi_byte: i32,
            wide_char_str: *mut u16,
            cch_wide_char: i32,
        ) -> i32;
    }

    pub fn decode(code_page: u32, bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return Some(String::new());
        }
        let len = i32::try_from(bytes.len()).ok()?;
        // SAFETY: `bytes` is a valid slice of `len` bytes and we pass `len`
        // explicitly; a null output buffer with a zero size is the documented
        // way to ask for the required length.
        let needed = unsafe { MultiByteToWideChar(code_page, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0) };
        if needed <= 0 {
            return None;
        }
        let mut buf = vec![0u16; needed as usize];
        // SAFETY: `buf` has room for exactly `needed` UTF-16 code units, which
        // is what the previous call reported.
        let written = unsafe {
            MultiByteToWideChar(code_page, 0, bytes.as_ptr(), len, buf.as_mut_ptr(), needed)
        };
        if written <= 0 {
            return None;
        }
        buf.truncate(written as usize);
        String::from_utf16(&buf).ok()
    }
}

#[cfg(not(windows))]
mod ansi {
    pub const CP_ACP: u32 = 0;
    pub fn decode(_code_page: u32, _bytes: &[u8]) -> Option<String> {
        None
    }
}

/// Read one newline-terminated message from the transport, or `None` at EOF.
///
/// Reads **bytes**, not a `String`: `BufRead::read_line` on a `String` returns
/// `InvalidData` for a non-UTF-8 line and there is no way to recover the
/// remaining stream, so one bad byte from one client would end the session.
fn read_message(reader: &mut impl BufRead, buf: &mut Vec<u8>) -> std::io::Result<Option<(String, &'static str)>> {
    buf.clear();
    let n = reader.read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(None);
    }
    // Trim the framing newline (and a CR, if the client writes CRLF).
    while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
        buf.pop();
    }
    Ok(Some(decode_line(buf)))
}

// ---------------------------------------------------------------------------
// JSON-RPC plumbing
// ---------------------------------------------------------------------------

fn handle_request(server: &Server, method: &str, params: &Value) -> Result<Value> {
    match method {
        "initialize" => Ok(json!({
            // Echo the client's revision when we implement it; the client
            // rejects a version it does not know, and a rejected handshake
            // means the tools never appear.  See
            // `SUPPORTED_PROTOCOL_VERSIONS`.
            "protocolVersion": negotiate_protocol_version(params),
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "magicmida-rs",
                "version": env!("CARGO_PKG_VERSION"),
            },
            // Server instructions are injected into the client's system prompt as
            // literal text, so keep them short and operational.
            "instructions": "Call `triage` first: it names the packer — Themida, VMProtect \
                             (min-protection/packed mode), or UPX — and the evidence. Themida \
                             targets: `unpack_start` + `unpack_status` (needs an interactive \
                             desktop session; the target opens its own window). VMProtect \
                             Packed: the code is not in the file, use the CLI's /dump-image \
                             --wait on the running process; MinProtection: /analyze is enough \
                             and works headless. UPX: fully static — the CLI's /unpack 
                             --packer upx restores the original with no process; 
                             /analyze reports the layout; no unpack_start."
        })),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("tools/call requires `name`"))?;
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            let result = match name {
                "triage" => tool_triage(&args),
                "unpack_start" => tool_unpack_start(server, &args),
                "unpack_status" => tool_unpack_status(server, &args),
                "unpack_cancel" => tool_unpack_cancel(server, &args),
                "verify" => tool_verify(&args),
                other => Err(anyhow!("unknown tool: {other}")),
            };

            match result {
                Ok(value) => Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into()),
                    }],
                    "isError": false,
                })),
                // Tool-level failures are reported as a result with `isError`,
                // not as a JSON-RPC error: the model must see the diagnosis
                // rather than a transport-level failure it cannot reason about.
                Err(e) => Ok(json!({
                    "content": [{ "type": "text", "text": format!("{e:#}") }],
                    "isError": true,
                })),
            }
        }
        "ping" => Ok(json!({})),
        other => Err(anyhow!("unsupported method: {other}")),
    }
}

fn main() -> Result<()> {
    // Logging must go to stderr: stdout is the protocol channel.  Writing a log
    // line to stdout would corrupt the JSON-RPC stream.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Both CLIs must sit next to this binary (same release dir), or be given
    // explicitly.  Resolving them once at startup means a misconfiguration is
    // reported before the client starts sending calls.
    //
    // Two builds are needed because the unpacker is architecture-specific: the
    // debugger's register layout follows the *host*, so a 64-bit `mida-cli`
    // refuses a 32-bit target outright.  The x86 build is optional — an
    // x64-only deployment is legitimate, and `unpack_start` explains the gap
    // precisely if an x86 target arrives.
    let cli_x64 = match std::env::var("MIDA_CLI") {
        Ok(p) => PathBuf::from(p),
        Err(_) => mida_run::find_cli()
            .ok_or_else(|| anyhow!("mida-cli.exe not found next to mida-mcp.exe; set MIDA_CLI"))?,
    };
    if !cli_x64.is_file() {
        return Err(anyhow!("mida-cli not found at {}", cli_x64.display()));
    }

    let cli_x86 = match std::env::var("MIDA_CLI_X86") {
        Ok(p) => Some(PathBuf::from(p)),
        Err(_) => {
            // Conventional location: same directory, distinct name, so both
            // builds can coexist in one release folder.
            let dir = cli_x64.parent().unwrap_or(Path::new("."));
            let candidate = dir.join("mida-cli-x86.exe");
            candidate.is_file().then_some(candidate)
        }
    };

    tracing::info!(
        x64 = %cli_x64.display(),
        x86 = cli_x86.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<none>".into()),
        "mida-mcp starting"
    );

    let server = Server::new(cli_x64, cli_x86);
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut raw = Vec::with_capacity(4096);

    loop {
        // Byte-level read: see `read_message`.  A `String`-based `read_line`
        // would end the session on the first non-UTF-8 byte a client sends.
        let (line, encoding) = match read_message(&mut reader, &mut raw) {
            Ok(Some(v)) => v,
            Ok(None) => break, // EOF: client closed the pipe.
            Err(e) => {
                tracing::warn!(error = %e, "transport read failed; ending session");
                break;
            }
        };
        if encoding != "utf-8" {
            tracing::warn!(
                encoding,
                "protocol line was not UTF-8; decoded with a fallback. \
                 Set the client's stdio encoding to UTF-8 to avoid this."
            );
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "ignoring malformed JSON-RPC line");
                continue;
            }
        };

        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));

        // Notifications (no id) need no reply.  `notifications/initialized` is
        // the one a client sends right after `initialize`.
        if id.is_none() {
            tracing::debug!(method, "notification");
            continue;
        }

        let response = match handle_request(&server, method, &params) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32603, "message": format!("{e:#}") },
            }),
        };

        let mut out = std::io::stdout();
        serde_json::to_writer(&mut out, &response)?;
        out.write_all(b"\n")?;
        out.flush()?;
    }

    // Do not leave orphaned CLI children behind when the client disconnects.
    if let Ok(jobs) = server.jobs.lock() {
        for handle in jobs.values() {
            if handle.finished().is_none() {
                kill_tree(handle.cli_pid);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_follows_the_cli_convention() {
        assert_eq!(
            default_output_path(Path::new("C:\\t\\x86_c.exe")),
            PathBuf::from("C:\\t\\x86_cU.exe")
        );
        assert_eq!(
            default_output_path(Path::new("C:\\t\\core.dll")),
            PathBuf::from("C:\\t\\coreU.dll")
        );
    }

    #[test]
    fn initialize_advertises_tools_and_instructions() {
        let server = Server::new(PathBuf::from("x"), None);
        let r = handle_request(&server, "initialize", &json!({})).unwrap();
        // No revision requested -> the preferred one, which must be a version a
        // real SDK actually lists.
        assert_eq!(r["protocolVersion"], PREFERRED_PROTOCOL_VERSION);
        assert!(r["capabilities"]["tools"].is_object());
        assert!(r["instructions"].as_str().unwrap().contains("triage"));
    }

    #[test]
    fn initialize_echoes_a_supported_client_revision() {
        // MCP `initialize` is a negotiation, not an announcement.  A client that
        // asks for a revision we implement must get that same revision back.
        let server = Server::new(PathBuf::from("x"), None);
        for v in SUPPORTED_PROTOCOL_VERSIONS {
            let r = handle_request(
                &server,
                "initialize",
                &json!({ "protocolVersion": v }),
            )
            .unwrap();
            assert_eq!(r["protocolVersion"], *v, "should echo {v}");
        }
    }

    #[test]
    fn initialize_falls_back_when_the_client_asks_for_an_unknown_revision() {
        // Measured 2026-10-24: the server used to hard-code "2026-07-28", which
        // DSH's SDK does not list, so the client refused the handshake with
        // "Server's protocol version is not supported" and the tools never
        // appeared.  An unknown request must degrade to a version we implement,
        // never to the caller's string.
        let server = Server::new(PathBuf::from("x"), None);
        let r = handle_request(
            &server,
            "initialize",
            &json!({ "protocolVersion": "2026-07-28" }),
        )
        .unwrap();
        assert_eq!(r["protocolVersion"], PREFERRED_PROTOCOL_VERSION);
        assert_ne!(r["protocolVersion"], "2026-07-28");
    }

    #[test]
    fn advertised_revisions_are_the_ones_dshs_sdk_lists() {
        // Pinned against the real list, so a future edit that invents a version
        // fails here rather than in a client's handshake.
        //
        // Source: `SUPPORTED_PROTOCOL_VERSIONS` exported by
        // `@modelcontextprotocol/client` 2.2.0 (the SDK `dsh-mcp-client` bundles).
        const SDK_LIST: &[&str] = &[
            "2025-11-25",
            "2025-06-18",
            "2025-03-26",
            "2024-11-05",
            "2024-10-07",
        ];
        for v in SUPPORTED_PROTOCOL_VERSIONS {
            assert!(SDK_LIST.contains(v), "{v} is not in the SDK's list");
        }
        assert_eq!(PREFERRED_PROTOCOL_VERSION, SDK_LIST[0]);
    }

    #[test]
    fn tools_list_names_every_tool_the_dispatcher_handles() {
        let server = Server::new(PathBuf::from("x"), None);
        let r = handle_request(&server, "tools/list", &json!({})).unwrap();
        let names: Vec<String> = r["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        for expected in [
            "triage",
            "unpack_start",
            "unpack_status",
            "unpack_cancel",
            "verify",
        ] {
            assert!(names.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[test]
    fn an_unknown_tool_is_a_tool_error_not_a_transport_error() {
        // The model must see the diagnosis; a JSON-RPC error would surface as a
        // transport failure it cannot reason about.
        let server = Server::new(PathBuf::from("x"), None);
        let r = handle_request(
            &server,
            "tools/call",
            &json!({ "name": "nope", "arguments": {} }),
        )
        .unwrap();
        assert_eq!(r["isError"], true);
        assert!(r["content"][0]["text"].as_str().unwrap().contains("unknown tool"));
    }

    #[test]
    fn a_missing_required_argument_is_reported_clearly() {
        let server = Server::new(PathBuf::from("x"), None);
        let r = handle_request(
            &server,
            "tools/call",
            &json!({ "name": "triage", "arguments": {} }),
        )
        .unwrap();
        assert_eq!(r["isError"], true);
        assert!(r["content"][0]["text"].as_str().unwrap().contains("`path` is required"));
    }

    #[test]
    fn an_unknown_job_id_is_reported_not_panicked() {
        let server = Server::new(PathBuf::from("x"), None);
        let r = handle_request(
            &server,
            "tools/call",
            &json!({ "name": "unpack_status", "arguments": { "job_id": "jobX" } }),
        )
        .unwrap();
        assert_eq!(r["isError"], true);
        assert!(r["content"][0]["text"].as_str().unwrap().contains("unknown job_id"));
    }

    #[test]
    fn an_unsupported_method_is_a_transport_error() {
        let server = Server::new(PathBuf::from("x"), None);
        assert!(handle_request(&server, "resources/list", &json!({})).is_err());
    }

    #[test]
    fn wait_budget_is_clamped_below_the_client_timeout() {
        // A caller asking for 10 minutes must not be honoured: the client gives
        // up at 60 s and the call would look hung.
        assert_eq!(600_000u64.min(MAX_WAIT_MS), MAX_WAIT_MS);
        assert!(MAX_WAIT_MS < 60_000, "must answer before the 60 s client timeout");
    }

    #[test]
    fn utf8_lines_are_decoded_as_utf8() {
        let (s, enc) = decode_line(b"{\"id\":1}");
        assert_eq!(s, "{\"id\":1}");
        assert_eq!(enc, "utf-8");
    }

    #[test]
    fn non_utf8_bytes_never_kill_the_session() {
        // Measured 2026-10-24: PowerShell's `StandardInputEncoding` defaults to
        // the console code page (GB2312 here), so a call carrying a Chinese
        // path arrived as GBK.  `BufRead::read_line` on a `String` returned
        // `InvalidData` and the `?` in `main` terminated the server — the client
        // saw a dead pipe with no diagnosis.
        //
        // The contract now: decoding always succeeds, whatever the bytes.
        let gbk = [0xCA, 0xB1, 0xB9, 0xE2]; // 时光 in GBK
        let (s, enc) = decode_line(&gbk);
        assert_ne!(enc, "utf-8");
        assert!(!s.is_empty(), "must produce *something* the parser can reject");
    }

    #[test]
    fn read_message_stops_at_eof_without_error() {
        let mut r = std::io::BufReader::new(&b""[..]);
        let mut buf = Vec::new();
        assert!(read_message(&mut r, &mut buf).unwrap().is_none());
    }

    #[test]
    fn read_message_trims_crlf_and_lf_alike() {
        let mut r = std::io::BufReader::new(&b"a\r\nb\n"[..]);
        let mut buf = Vec::new();
        assert_eq!(read_message(&mut r, &mut buf).unwrap().unwrap().0, "a");
        assert_eq!(read_message(&mut r, &mut buf).unwrap().unwrap().0, "b");
        assert!(read_message(&mut r, &mut buf).unwrap().is_none());
    }

    #[test]
    fn a_bad_line_does_not_consume_the_rest_of_the_stream() {
        // The whole point of byte-level reading: the next line must still arrive.
        let mut r = std::io::BufReader::new(&[0xFFu8, 0xFE, b'\n', b'o', b'k', b'\n'][..]);
        let mut buf = Vec::new();
        let first = read_message(&mut r, &mut buf).unwrap().unwrap();
        assert_ne!(first.1, "utf-8");
        let second = read_message(&mut r, &mut buf).unwrap().unwrap();
        assert_eq!(second.0, "ok");
        assert_eq!(second.1, "utf-8");
    }

    // -- triage classification ----------------------------------------------
    //
    // The fixture mirrors `mida_packers_vmprotect::test_support`, which is
    // `pub(crate)` and therefore not reachable from here.  The section shapes
    // are the measured ones used by the detector's own tests, so a verdict
    // proven there must survive the trip through triage's JSON.

    use mida_pe::{
        ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders,
        ImageOptionalHeader, ImageSectionHeader, PeHeader, PeSection,
    };

    fn fixture_pe(sections: Vec<PeSection>) -> PeHeader {
        let n = sections.len() as u16;
        PeHeader {
            dos_header: ImageDosHeader { e_magic: 0x5a4d, e_lfanew: 0x80 },
            nt_headers: ImageNtHeaders {
                signature: 0x0000_4550,
                file_header: ImageFileHeader {
                    machine: 0x8664,
                    number_of_sections: n,
                    time_date_stamp: 0,
                    size_of_optional_header: 0xf0,
                    characteristics: 0x22,
                },
                optional_header: ImageOptionalHeader {
                    magic: 0x20b,
                    major_linker_version: 14,
                    minor_linker_version: 44,
                    size_of_code: 0,
                    size_of_initialized_data: 0,
                    size_of_uninitialized_data: 0,
                    address_of_entry_point: 0,
                    base_of_code: 0,
                    base_of_data: None,
                    image_base: 0x1_4000_0000,
                    section_alignment: 0x1000,
                    file_alignment: 0x200,
                    major_operating_system_version: 6,
                    minor_operating_system_version: 0,
                    major_image_version: 0,
                    minor_image_version: 0,
                    major_subsystem_version: 6,
                    minor_subsystem_version: 0,
                    win32_version_value: 0,
                    size_of_image: 0,
                    size_of_headers: 0x400,
                    check_sum: 0,
                    subsystem: 2,
                    dll_characteristics: 0x8160,
                    size_of_stack_reserve: 0,
                    size_of_stack_commit: 0,
                    size_of_heap_reserve: 0,
                    size_of_heap_commit: 0,
                    loader_flags: 0,
                    number_of_rva_and_sizes: 16,
                    data_directory: [ImageDataDirectory::default(); 16],
                },
            },
            sections,
            image_base: 0x1_4000_0000,
            entry_point: 0,
            is_64bit: true,
            file_alignment: 0x200,
            section_alignment: 0x1000,
        }
    }

    fn fixture_sec(
        name: &str,
        raw_size: u32,
        virtual_size: u32,
        chars: u32,
        raw_offset: u32,
    ) -> PeSection {
        PeSection {
            header: ImageSectionHeader {
                name: [0; 8],
                virtual_size,
                virtual_address: 0,
                size_of_raw_data: raw_size,
                pointer_to_raw_data: raw_offset,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: chars,
            },
            name: name.to_string(),
            virtual_address: 0,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics: chars,
            extra_data: None,
        }
    }

    fn evidence_codes(v: &Value, key: &str) -> Vec<String> {
        v["packer"][key]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["code"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn triage_names_the_vmprotect_mode_and_the_evidence() {
        // The 伦伦 MinProtection shape from the detector's own tests.
        let img = vec![0u8; 0x1000];
        let pe = fixture_pe(vec![
            fixture_sec(".text", 0x400, 0x400, 0x6000_0020, 0x0),
            fixture_sec(".fptable", 0x200, 0x100, 0xc000_0040, 0x0),
            fixture_sec(".vmp0", 0x400, 0x400, 0x6800_0060, 0x400),
        ]);
        let r = triage_report(&pe, &img);
        assert_eq!(r["packer"]["family"], "VMProtect");
        assert_eq!(r["packer"]["mode"], "min-protection");
        assert_eq!(r["packer"]["summary"], "VMProtect (min-protection)");
        let codes = evidence_codes(&r, "evidence");
        assert!(codes.contains(&"vmp-section".to_string()));
        assert!(codes.contains(&"notpaged-executable-section".to_string()));
        assert!(codes.contains(&"fptable-section".to_string()));
        assert!(codes.contains(&"runtime-section".to_string()));
        assert_eq!(r["packer"]["absent"], json!([]));
        assert_eq!(r["likely_themida"], false);
        assert!(r["hint"].as_str().unwrap().contains("/analyze"));
    }

    #[test]
    fn triage_names_the_packed_mode_and_points_at_the_live_pipeline() {
        // The zz_test Packed shape: `.text` has no file bytes, the VM code
        // lives in `.rdata2`.
        let img = vec![0u8; 0x1000];
        let pe = fixture_pe(vec![
            fixture_sec(".text", 0, 0x12b05c, 0x6000_0020, 0),
            fixture_sec(".fptable", 0, 0x100, 0xc000_0040, 0),
            fixture_sec(".rdata2", 0x400, 0x400, 0x6800_0060, 0x400),
        ]);
        let r = triage_report(&pe, &img);
        assert_eq!(r["packer"]["family"], "VMProtect");
        assert_eq!(r["packer"]["mode"], "packed");
        // The name marker is absent and the verdict says so instead of
        // silently omitting it — the same contract the CLI's /analyze keeps.
        assert!(evidence_codes(&r, "absent").contains(&"vmp-section".to_string()));
        assert!(r["hint"].as_str().unwrap().contains("/dump-image"));
        assert!(r["hint"].as_str().unwrap().contains("will refuse"));
    }

    #[test]
    fn triage_keeps_themida_as_a_verdict_with_marker_evidence() {
        let img = vec![0u8; 0x1000];
        let pe = fixture_pe(vec![
            fixture_sec("        ", 0x4c600, 0xdd9a0, 0x6000_0020, 0),
            fixture_sec(".winlice", 0, 0x6d6000, 0xe000_0060, 0),
            fixture_sec(".boot", 0x4e8800, 0x4e8800, 0x6000_0060, 0),
        ]);
        let r = triage_report(&pe, &img);
        assert_eq!(r["packer"]["family"], "Themida");
        assert_eq!(r["packer"]["mode"], Value::Null);
        let codes = evidence_codes(&r, "evidence");
        assert!(codes.contains(&"winlice-section".to_string()));
        assert!(codes.contains(&"boot-section".to_string()));
        // Compatibility fields survive for the tool's first callers.
        assert_eq!(r["themida_markers"]["winlice"], true);
        assert_eq!(r["themida_markers"]["boot"], true);
        assert_eq!(r["likely_themida"], true);
        assert!(r["hint"].as_str().unwrap().contains("unpack_start"));
    }

    #[test]
    fn triage_reports_unknown_for_an_ordinary_pe() {
        let img = vec![0u8; 0x1000];
        let pe = fixture_pe(vec![fixture_sec(".text", 0x200, 0x200, 0x6000_0020, 0x200)]);
        let r = triage_report(&pe, &img);
        assert_eq!(r["packer"]["family"], "unknown");
        assert_eq!(r["packer"]["mode"], Value::Null);
        assert_eq!(r["packer"]["evidence"], json!([]));
        assert_eq!(r["likely_themida"], false);
        assert!(r["hint"].as_str().unwrap().contains("No recognised packer"));
    }

    #[test]
    fn triage_classifies_upx_and_points_at_the_static_pipeline() {
        // A synthetic UPX image: the same shape the upx crate's own tests use,
        // with a checksum-valid PackHeader (built with UPX's own rule).
        let mut img = vec![0u8; 0x1000];
        let mut header = vec![0u8; 32];
        header[0..4].copy_from_slice(b"UPX!");
        header[4] = 13; // version
        header[5] = 36; // format: PE32+/AMD64
        header[6] = 8; // method: NRV2E_LE32
        header[7] = 7; // level
        header[8..12].copy_from_slice(&0xC6_4A_16_1Fu32.to_le_bytes()); // u_adler
        header[12..16].copy_from_slice(&0u32.to_le_bytes()); // c_adler (zeros below)
        header[16..20].copy_from_slice(&1_000_000u32.to_le_bytes()); // u_len
        header[20..24].copy_from_slice(&100_000u32.to_le_bytes()); // c_len
        header[24..28].copy_from_slice(&2_000_000u32.to_le_bytes()); // u_file_size
        header[28] = 73; // filter
        header[29] = 55; // filter_cto
        header[30] = 0; // n_mru
        let sum: u32 = header[4..31].iter().map(|&b| b as u32).sum();
        header[31] = (sum % 251) as u8;
        img[0x200..0x205].copy_from_slice(b"5.21\0");
        img[0x205..0x225].copy_from_slice(&header);

        let pe = fixture_pe(vec![
            fixture_sec("UPX0", 0, 0x2d6000, 0xe000_0080, 0),
            fixture_sec("UPX1", 0x14fc00, 0x150000, 0xe000_0040, 0x200),
        ]);
        let r = triage_report(&pe, &img);
        assert_eq!(r["packer"]["family"], "UPX");
        assert_eq!(r["packer"]["mode"], Value::Null);
        let codes: Vec<String> = r["packer"]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["code"].as_str().unwrap().to_string())
            .collect();
        assert!(codes.contains(&"upx-packheader".to_string()));
        assert!(codes.contains(&"upx-sections".to_string()));
        // UPX0 has exactly the shape is_themida_section keys on, so the gate
        // order must have kept it out of the Themida verdict.
        assert_eq!(r["likely_themida"], false);
        assert!(r["hint"].as_str().unwrap().contains("statically-decodable"));
    }
}


