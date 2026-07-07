//! Magicmida-RS — Themida automatic unpacker (CLI entry point).
//!
//! ## Usage
//!
//! ```text
//! magicmida /unpack <filename> [--data-sections] [--shrink] [-v]
//! magicmida /dump-process <pid> <unpacked-file>
//! ```

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
            eprintln!("  magicmida /unpack <filename> [--data-sections] [--shrink] [-v]");
            eprintln!("  magicmida /dump-process <pid> <unpacked-file>");
            eprintln!("  magicmida /verify <unpacked-file> <reference-file>");
            std::process::exit(1);
        }
    };

    // Initialise logging — verbose mode enables debug-level output.
    let verbose = matches!(cmd, args::Command::Unpack { verbose: true, .. });
    log::init_logging(verbose);

    // Dispatch.
    if let Err(e) = commands::run_command(cmd) {
        log::log(log::LogType::Fatal, &format!("Fatal error: {:#}", e));
        std::process::exit(1);
    }
}
