//! Log output — colourful, tracing-backed console logging.
//!
//! Corresponds to `TLogMsgType` in `Utils.pas` and the `ConsoleLog` procedure
//! in `Magicmida.dpr`.

use std::io;
use tracing::Level;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::FmtSubscriber;

// ---------------------------------------------------------------------------
// LogType
// ---------------------------------------------------------------------------

/// Log severity / colour tag — matches `TLogMsgType` in `Utils.pas`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogType {
    /// General informational message (white / default terminal colour).
    Info,
    /// Positive / success message (green).
    Good,
    /// Warning message — non-fatal difference or potential issue (yellow).
    Warn,
    /// Fatal error — execution cannot continue (red).
    Fatal,
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/// Initialise the tracing subscriber for console output.
///
/// When `verbose` is `true`, the subscriber is configured at `DEBUG` level;
/// otherwise it runs at `INFO`.  The output format mimics the Pascal reference:
///
/// ```text
/// [HH:MM:SS] [INFO] message
/// [HH:MM:SS] [GOOD] message
/// [HH:MM:SS] [FATAL] message
/// ```
///
/// Colours are applied to the severity tag:
/// - `GOOD` → green
/// - `FATAL` → red
/// - `INFO` / `DEBUG` / `WARN` → default
pub fn init_logging(verbose: bool) {
    let default_level = if verbose { "debug" } else { "info" };

    let subscriber = FmtSubscriber::builder()
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .with_level(true)
        .with_writer(io::stderr)
        .with_timer(SystemTime)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .event_format(LogFormatter)
        .finish();

    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("Warning: failed to set global tracing subscriber: {e}");
    }
}

/// Emit a log line with the given severity and colour.
///
/// This is the main entry point for all user-facing logging.  It maps the
/// [`LogType`] to the nearest [`tracing::Level`] and calls the corresponding
/// `tracing` macro so the subscriber formats and colours it.
pub fn log(log_type: LogType, msg: &str) {
    match log_type {
        LogType::Info => tracing::info!("{}", msg),
        LogType::Good => tracing::info!(target: "good", "{}", msg),
        LogType::Warn => tracing::warn!("{}", msg),
        LogType::Fatal => tracing::error!("{}", msg),
    }
}

// ---------------------------------------------------------------------------
// Custom formatter — maps "good" target to green output
// ---------------------------------------------------------------------------

struct LogFormatter;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for LogFormatter
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        // Record timestamp.
        let meta = event.metadata();
        let now = SystemTime;

        // Emit a compact "[HH:MM:SS]" prefix.
        write!(writer, "[")?;
        now.format_time(&mut writer)?;
        write!(writer, "] ")?;

        // Emit the level tag, colored appropriately.
        let level = *meta.level();
        let is_good = meta.target() == "good";

        match (level, is_good) {
            (Level::ERROR, _) => {
                // Fatal — red
                write!(writer, "\x1b[31m[FATAL]\x1b[0m ")?;

                // Also emit a platform beep for fatal messages,
                // matching the Pascal reference's `MessageBeep`.
                #[cfg(windows)]
                {
                    let _ = std::io::Write::write_all(
                        &mut io::stdout(),
                        &[0x07u8],
                    );
                }
            }
            (_, true) => {
                // Good — green
                write!(writer, "\x1b[32m[GOOD]\x1b[0m ")?;
            }
            (Level::WARN, _) => {
                write!(writer, "\x1b[33m[WARN]\x1b[0m ")?;
            }
            (Level::DEBUG, _) => {
                write!(writer, "[DEBUG] ")?;
            }
            _ => {
                // Info — default colour
                write!(writer, "[INFO] ")?;
            }
        }

        // Emit the log message.
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}
