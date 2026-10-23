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
    pub fn spawn(cli: &Path, input: &Path, output: &Path, verbose: bool) -> std::io::Result<Job> {
        let mut cmd = Command::new(cli);
        cmd.arg("/unpack").arg(input).arg("-o").arg(output);
        if verbose {
            cmd.arg("-v");
        }
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
        let _ = Command::new("taskkill")
            .args(["/PID", &self.cli_pid.to_string(), "/T", "/F"])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output();
    }
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
