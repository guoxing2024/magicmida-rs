//! Child-process management for the GUI: spawning `mida-cli`, streaming its
//! output on a background thread, and cancelling the run.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// `creation_flags` lives on this trait; without the import the calls below do
// not resolve even though the platform supports them.
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};

use crate::parse::{RunState, TargetKind};

/// A message sent from the reader thread to the UI thread.
pub enum Event {
    /// A line arrived and should be fed to the parser.
    Line(String),
    /// The child exited with this status code.
    Exited(i32),
}

/// Which packer branch the spawned CLI should take.
///
/// Mirrors the CLI's `--packer` values; `Auto` (the CLI default) is better
/// left off the command line entirely, so [`PackerChoice::cli_value`] maps it
/// to `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackerChoice {
    /// Detect the packer and refuse what the Themida pipeline cannot handle.
    Auto,
    /// Force the Themida branch.
    Themida,
    /// VMProtect branch (experimental).
    VmProtect,
    /// UPX static unpacker — no process, no desktop session.
    Upx,
}

impl PackerChoice {
    /// All choices, in dropdown order.
    pub const ALL: [PackerChoice; 4] = [
        PackerChoice::Auto,
        PackerChoice::Themida,
        PackerChoice::VmProtect,
        PackerChoice::Upx,
    ];

    /// GUI label (Chinese, matching the rest of the front-end).
    pub fn label(&self) -> &'static str {
        match self {
            PackerChoice::Auto => "自动检测",
            PackerChoice::Themida => "Themida",
            PackerChoice::VmProtect => "VMProtect",
            PackerChoice::Upx => "UPX",
        }
    }

    /// Value for the CLI's `--packer` flag; `None` for the default (auto).
    pub fn cli_value(&self) -> Option<&'static str> {
        match self {
            PackerChoice::Auto => None,
            PackerChoice::Themida => Some("themida"),
            PackerChoice::VmProtect => Some("vmprotect"),
            PackerChoice::Upx => Some("upx"),
        }
    }
}

/// Options for [`Job::spawn_with`] — the CLI flags a front-end can set.
///
/// Defaults mirror the CLI's own defaults exactly, so a front-end that passes
/// `SpawnOptions::default()` produces the same command line the old
/// `spawn(cli, input, output, verbose)` call always built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnOptions {
    /// Add `-v` (floods the log with the debug event stream).
    pub verbose: bool,
    /// Packer branch (`--packer`).
    pub packer: PackerChoice,
    /// Restore `.rdata` / `.data` from the process (`--data-sections`).
    pub data_sections: bool,
    /// Drop Themida sections (`--shrink` default on in the CLI; pass
    /// `false` here and `--no-shrink` lands on the command line).
    pub shrink: bool,
}

impl Default for SpawnOptions {
    fn default() -> Self {
        Self {
            verbose: false,
            packer: PackerChoice::Auto,
            data_sections: false,
            shrink: true,
        }
    }
}

/// Build the argument list for an unpack run — pure, so the exact command
/// line a front-end produces is unit-testable.
///
/// Only non-defaults are passed: `--packer` only when a branch is forced,
/// `--data-sections` only when requested, `--no-shrink` only when the CLI's
/// default shrink would be unwanted, `-v` only when verbose.
pub fn unpack_args(input: &Path, output: &Path, opts: &SpawnOptions) -> Vec<String> {
    let mut args = vec![
        "/unpack".to_string(),
        input.display().to_string(),
        "-o".to_string(),
        output.display().to_string(),
    ];
    if let Some(p) = opts.packer.cli_value() {
        args.push("--packer".to_string());
        args.push(p.to_string());
    }
    if opts.data_sections {
        args.push("--data-sections".to_string());
    }
    if !opts.shrink {
        args.push("--no-shrink".to_string());
    }
    if opts.verbose {
        args.push("-v".to_string());
    }
    args
}

/// A running unpack job.
pub struct Job {
    rx: Receiver<Event>,
    pub state: Arc<Mutex<RunState>>,
    pub started_at: std::time::Instant,
    /// PID of the `mida-cli` process itself.
    ///
    /// Kept separate from `state.metrics.pid`: that one is the *debuggee*, and
    /// killing it leaves the CLI running with its debug loop waiting on a dead
    /// process.  Cancellation has to target this one, with `/T` to take the
    /// debuggee and the loader host with it.
    cli_pid: u32,
}

impl Job {
    /// Spawn `mida-cli /unpack <input> -o <output>` and start reading its output.
    ///
    /// `verbose` adds `-v`, which floods the log with the debug event stream.
    /// The GUI defaults to non-verbose so the trace table stays readable.
    ///
    /// Kept as the minimal surface for callers with fixed options (the MCP
    /// server); front-ends that expose the CLI's flags use [`Job::spawn_with`].
    pub fn spawn(cli: &Path, input: &Path, output: &Path, verbose: bool) -> std::io::Result<Job> {
        Self::spawn_with(
            cli,
            input,
            output,
            SpawnOptions {
                verbose,
                ..SpawnOptions::default()
            },
        )
    }

    /// Spawn an unpack run with explicit front-end options.
    ///
    /// The command line is built by [`unpack_args`]; everything else (reader
    /// threads, exit watcher, cancellation handle) is identical to [`Job::spawn`].
    pub fn spawn_with(
        cli: &Path,
        input: &Path,
        output: &Path,
        opts: SpawnOptions,
    ) -> std::io::Result<Job> {
        let mut cmd = Command::new(cli);
        cmd.args(unpack_args(input, output, &opts));
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Never pop a console window for the child.
            .creation_flags(0x0800_0000); // CREATE_NO_WINDOW

        let mut child = cmd.spawn()?;

        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        let (tx, rx) = mpsc::channel::<Event>();
        let state = Arc::new(Mutex::new(RunState::with_kind(TargetKind::of_path(input))));

        // Two reader threads: the CLI logs to stderr (tracing) but may also
        // print to stdout (usage text, panics).
        spawn_reader(stdout, tx.clone());
        spawn_reader(stderr, tx.clone());

        // A third thread waits for the exit status so the UI can react without
        // polling `try_wait` in a tight loop.
        let mut wait_child = child;
        // NOTE: `Child::wait` needs &mut, so hand ownership to this thread and
        // keep a handle to kill it through a separate channel-free path.
        let pid = wait_child.id();
        std::thread::spawn(move || {
            let code = wait_child
                .wait()
                .map(|s| s.code().unwrap_or(-1))
                .unwrap_or(-1);
            let _ = tx.send(Event::Exited(code));
        });

        Ok(Job {
            rx,
            state,
            started_at: std::time::Instant::now(),
            cli_pid: pid,
        })
    }

    /// Drain everything that has arrived since the last call.
    ///
    /// Returns `Some(exit_code)` once the process has exited.
    pub fn pump(&mut self) -> (bool, Option<i32>) {
        let mut dirty = false;
        let mut exit = None;
        loop {
            match self.rx.try_recv() {
                Ok(Event::Line(l)) => {
                    let milestone = self
                        .state
                        .lock()
                        .map(|mut s| s.feed(&l))
                        .unwrap_or(false);
                    dirty |= milestone;
                }
                Ok(Event::Exited(code)) => {
                    exit = Some(code);
                    dirty = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        (dirty, exit)
    }

    /// PID of the `mida-cli` process itself.
    ///
    /// Exposed because the MCP server hands ownership of the [`Job`] to a pump
    /// thread, so it cannot call [`Job::cancel`] (which needs `&mut self`).
    /// Cancellation must target *this* PID, never the debuggee.
    #[must_use]
    pub fn cli_pid(&self) -> u32 {
        self.cli_pid
    }

    /// Ask the child to stop.
    ///
    /// The process handle lives on the waiter thread, so cancellation goes
    /// through `taskkill` rather than `Child::kill`.
    ///
    /// Target the **CLI**, not the debuggee.  An earlier version used
    /// `metrics.pid` (the debuggee) — that kills the thing being unpacked and
    /// leaves `mida-cli` spinning in `WaitForDebugEvent` on a dead process, so
    /// the run never ends and the Cancel button looks inert.  `/T` takes the
    /// debuggee and, on the DLL path, the generated loader host with it.
    pub fn cancel(&mut self) {
        if let Ok(state) = self.state.lock() {
            if state.finished.is_some() {
                return;
            }
        }
        kill_tree(self.cli_pid);
    }
}

/// Kill a process and its whole tree.
///
/// Shared by [`Job::cancel`] and the MCP server's cancel path so both use the
/// same `/T` semantics — killing only the CLI would leave the debuggee (and, on
/// the DLL path, the generated loader host) running.
pub fn kill_tree(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output();
}

/// Read a pipe line by line into the channel.
fn spawn_reader<R: Read + Send + 'static>(pipe: R, tx: mpsc::Sender<Event>) {
    std::thread::spawn(move || {
        let reader = BufReader::new(pipe);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if tx.send(Event::Line(l)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

/// Locate `mida-cli.exe` next to the GUI executable, then fall back to the
/// build tree.
pub fn find_cli() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;

    let beside = dir.join("mida-cli.exe");
    if beside.is_file() {
        return Some(beside);
    }

    // target/<profile>/mida-gui.exe -> look in the same profile dir for the
    // release build as a convenience during development.
    for profile in ["release", "debug"] {
        let candidate = dir
            .parent()
            .map(|p| p.join(profile).join("mida-cli.exe"))
            .filter(|p| p.is_file());
        if let Some(c) = candidate {
            return Some(c);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_reproduce_the_old_command_line() {
        // The MCP server spawns through `spawn`, which now delegates to
        // `spawn_with` + `unpack_args`; the defaults must keep producing
        // exactly what the old hand-built call produced.
        let args = unpack_args(
            Path::new("D:\\t\\target.exe"),
            Path::new("D:\\t\\targetU.exe"),
            &SpawnOptions::default(),
        );
        assert_eq!(
            args,
            vec![
                "/unpack",
                "D:\\t\\target.exe",
                "-o",
                "D:\\t\\targetU.exe",
            ]
        );
    }

    #[test]
    fn every_non_default_lands_on_the_command_line() {
        let opts = SpawnOptions {
            verbose: true,
            packer: PackerChoice::Upx,
            data_sections: true,
            shrink: false,
        };
        let args = unpack_args(Path::new("in.exe"), Path::new("out.exe"), &opts);
        assert_eq!(
            args,
            vec![
                "/unpack",
                "in.exe",
                "-o",
                "out.exe",
                "--packer",
                "upx",
                "--data-sections",
                "--no-shrink",
                "-v",
            ]
        );
    }

    #[test]
    fn auto_is_left_off_the_command_line() {
        // `--packer auto` is the CLI's default; spelling it out would only
        // make every spawned command line noisier.
        let opts = SpawnOptions {
            packer: PackerChoice::Auto,
            ..SpawnOptions::default()
        };
        let args = unpack_args(Path::new("in.exe"), Path::new("out.exe"), &opts);
        assert!(!args.windows(2).any(|w| w[0] == "--packer"));
    }

    #[test]
    fn packer_choices_map_to_the_cli_values() {
        assert_eq!(PackerChoice::Auto.cli_value(), None);
        assert_eq!(PackerChoice::Themida.cli_value(), Some("themida"));
        assert_eq!(PackerChoice::VmProtect.cli_value(), Some("vmprotect"));
        assert_eq!(PackerChoice::Upx.cli_value(), Some("upx"));
        // The dropdown covers every choice, so a new variant cannot be added
        // without a label.
        assert_eq!(PackerChoice::ALL.len(), 4);
        for p in PackerChoice::ALL {
            assert!(!p.label().is_empty());
        }
    }
}

