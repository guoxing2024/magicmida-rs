//! Command dispatch — maps CLI commands to unpacker functions.

use crate::args::Command;

/// Execute a parsed [`Command`].
///
/// # Errors
///
/// Returns an [`anyhow::Error`] when the command fails.
pub fn run_command(cmd: Command) -> Result<(), anyhow::Error> {
    match cmd {
        Command::Unpack {
            input,
            output,
            create_data_sections,
            shrink,
            verbose: _,
        } => crate::unpacker::unpack(&input, output.as_deref(), create_data_sections, shrink),
        Command::DumpProcess {
            pid,
            unpacked_file,
        } => crate::unpacker::dump_process_code(pid, &unpacked_file),
        Command::Verify {
            unpacked,
            reference,
        } => crate::unpacker::verify_unpacked(&unpacked, &reference),
        Command::Version => {
            println!("mida-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Help => {
            println!("Magicmida-RS {}", env!("CARGO_PKG_VERSION"));
            println!("Themida automatic unpacker.");
            println!();
            println!("Usage:");
            println!("  mida-cli /unpack <filename> [--data-sections] [--shrink] [-v]");
            println!("  mida-cli /dump-process <pid> <unpacked-file>");
            println!("  mida-cli /verify <unpacked-file> <reference-file>");
            println!("  mida-cli /version | /help");
            Ok(())
        }
    }
}
