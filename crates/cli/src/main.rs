//! Magicmida-RS — Themida automatic unpacker (CLI entry point).
//!
//! ## Usage
//!
//! ```text
//! mida-cli                      guided interactive mode (beginner-friendly)
//! mida-cli /unpack <filename> [--data-sections] [--shrink] [-v]
//! mida-cli /analyze <filename> [--extract <dir>] [-v]
//! mida-cli /dump-process <pid> <unpacked-file>
//! ```

mod analyze;
mod args;
mod commands;
mod dump_image;
mod interactive;
mod log;
mod unpacker;

fn main() {
    let cmd = match args::parse_args() {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("提示：不带参数运行 mida-cli 可进入引导模式。");
            std::process::exit(1);
        }
    };

    // Initialise logging — verbose mode enables debug-level output.
    //
    // The interactive wizard initialises its own subscriber (once, before its
    // first command): a second `set_global_default` here would just print a
    // "failed to set" warning on every wizard run.
    if !matches!(cmd, args::Command::Interactive { .. }) {
        let verbose = matches!(
            cmd,
            args::Command::Unpack { verbose: true, .. } | args::Command::Analyze { verbose: true, .. }
        );
        log::init_logging(verbose);
    }

    // Dispatch.
    if let Err(e) = commands::run_command(cmd) {
        log::log(log::LogType::Fatal, &format!("Fatal error: {:#}", e));
        std::process::exit(1);
    }
}
