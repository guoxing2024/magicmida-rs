//! Magicmida-RS — Themida automatic unpacker (CLI entry point).
//!
//! ## Usage
//!
//! ```text
//! mida-cli /unpack <filename> [--data-sections] [--shrink] [-v]
//! mida-cli /analyze <filename> [--extract <dir>] [-v]
//! mida-cli /dump-process <pid> <unpacked-file>
//! ```

mod analyze;
mod args;
mod commands;
mod log;
mod unpacker;

fn main() {
    let cmd = match args::parse_args() {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Usage:");
            eprintln!("  mida-cli /unpack <filename> [--data-sections] [--shrink] [-v]");
            eprintln!("  mida-cli /analyze <filename> [--extract <dir>] [-v]");
            eprintln!("  mida-cli /dump-process <pid> <unpacked-file>");
            eprintln!("  mida-cli /verify <unpacked-file> <reference-file>");
            std::process::exit(1);
        }
    };

    // Initialise logging — verbose mode enables debug-level output.
    let verbose = matches!(
        cmd,
        args::Command::Unpack { verbose: true, .. } | args::Command::Analyze { verbose: true, .. }
    );
    log::init_logging(verbose);

    // Dispatch.
    if let Err(e) = commands::run_command(cmd) {
        log::log(log::LogType::Fatal, &format!("Fatal error: {:#}", e));
        std::process::exit(1);
    }
}
