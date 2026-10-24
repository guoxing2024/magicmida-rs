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
use serde_json::{json, Value};

use mida_run::{kill_tree, Job, Phase, RunReport, RunState};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Protocol revision we advertise.  Clients negotiate; this is the value DSH's
/// SDK sends when it selects the modern revision.
const PROTOCOL_VERSION: &str = "2026-07-28";

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

/// `triage` — PE facts without running anything.  Useful as the first call: it
/// answers "is this even a packed target, and which architecture?" cheaply.
fn tool_triage(args: &Value) -> Result<Value> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`path` is required"))?;
    let pe = mida_pe::PeHeader::from_file(Path::new(path))
        .map_err(|e| anyhow!("cannot parse {path}: {e}"))?;

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

    // The Themida markers this project keys on.  Reporting them here means an
    // agent can decide whether `/unpack` is worth attempting before paying for
    // a full run.
    let has_winlice = pe.sections.iter().any(|s| s.name.contains(".winlice"));
    let has_boot = pe.sections.iter().any(|s| s.name.contains(".boot"));
    let has_themida = pe.sections.iter().any(|s| s.name.contains(".themida"));
    let unnamed_exec_write = pe.sections.iter().any(|s| {
        s.name.is_empty()
            && s.characteristics & 0x2000_0000 != 0
            && s.characteristics & 0x8000_0000 != 0
    });

    Ok(json!({
        "architecture": if pe.is_64bit { "x64" } else { "x86" },
        "image_base": format!("{:#x}", pe.image_base),
        "entry_point_rva": format!("{:#x}", pe.entry_point),
        "size_of_image": format!("{:#x}", pe.size_of_image()),
        "sections": sections,
        "themida_markers": {
            "winlice": has_winlice,
            "boot": has_boot,
            "themida": has_themida,
            "unnamed_exec_write": unnamed_exec_write,
        },
        "likely_themida": has_winlice || has_boot || has_themida || unnamed_exec_write,
        "hint": if pe.is_64bit {
            "x64: verified path (golden record exists)"
        } else {
            "x86: pipeline runs end-to-end but the product's import wiring is not yet \
             correct (measured: loader accepts the image, then ENTRYPOINT_NOT_FOUND)"
        },
    }))
}

// ---------------------------------------------------------------------------
// Tool catalogue
// ---------------------------------------------------------------------------

fn tool_definitions() -> Value {
    json!([
        {
            "name": "triage",
            "description": "Report PE facts and Themida markers for a binary without running it. \
                            Call this first to decide whether unpacking is worthwhile and which \
                            architecture path applies.",
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
// JSON-RPC plumbing
// ---------------------------------------------------------------------------

fn handle_request(server: &Server, method: &str, params: &Value) -> Result<Value> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "magicmida-rs",
                "version": env!("CARGO_PKG_VERSION"),
            },
            // Server instructions are injected into the client's system prompt as
            // literal text, so keep them short and operational.
            "instructions": "Themida unpacker. Call `triage` first to confirm the target is packed and \
                             learn its architecture. Then `unpack_start` + `unpack_status`. \
                             Unpacking needs an interactive desktop session (the target opens its own \
                             window); it will not work headless. x64 is the verified path; x86 runs \
                             but its product currently fails to resolve imports."
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
    let mut line = String::new();

    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break; // EOF: client closed the pipe.
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
        assert_eq!(r["protocolVersion"], PROTOCOL_VERSION);
        assert!(r["capabilities"]["tools"].is_object());
        assert!(r["instructions"].as_str().unwrap().contains("triage"));
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
}


