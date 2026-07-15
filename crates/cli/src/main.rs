//! Magicmida-RS — Themida automatic unpacker (CLI entry point).

mod args;
mod commands;
mod log;
mod unpacker;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = env!("CARGO_PKG_NAME");

fn print_help() {
    println!("Magicmida-RS v{} - Themida Automatic Unpacker", VERSION);
    println!();
    println!("USAGE:");
    println!("  {} [COMMAND] [OPTIONS]", NAME);
    println!();
    println!("COMMANDS:");
    println!("  /unpack <file> [options]     Unpack a Themida-protected executable");
    println!("  /dump-process <pid> <file>   Dump devirtualized .text from running process");
    println!("  /verify <unpacked> <ref>     Verify unpacked file against reference");
    println!();
    println!("UNPACK OPTIONS:");
    println!("  -o, --output <file>          Output path (default: <input>U.exe)");
    println!("  --data-sections              Restore .rdata/.data sections from process");
    println!("  --shrink                     Remove Themida-specific sections (default)");
    println!("  --no-shrink                  Keep all sections");
    println!("  -v, --verbose                Enable debug logging");
    println!();
    println!("GLOBAL OPTIONS:");
    println!("  -h, --help                   Show this help message");
    println!("  -V, --version                Show version information");
    println!();
    println!("EXAMPLES:");
    println!("  {} /unpack protected.exe", NAME);
    println!("  {} /unpack app.exe -o unpacked.exe --verbose", NAME);
    println!("  {} /verify unpacked.exe reference.exe", NAME);
}

fn print_version() {
    println!("{} {}", NAME, VERSION);
}

fn main() {
    let cmd = match args::parse_args() {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!();
            eprintln!("Run '{} --help' for usage information.", NAME);
            std::process::exit(1);
        }
    };

    // Handle meta commands
    match cmd {
        args::Command::Help => {
            print_help();
            std::process::exit(0);
        }
        args::Command::Version => {
            print_version();
            std::process::exit(0);
        }
        _ => {}
    }

    // Initialise logging — verbose mode enables debug-level output.
    let verbose = matches!(cmd, args::Command::Unpack { verbose: true, .. });
    log::init_logging(verbose);

    // Dispatch.
    if let Err(e) = commands::run_command(cmd) {
        log::log(log::LogType::Fatal, &format!("Fatal error: {:#}", e));
        std::process::exit(1);
    }
}
