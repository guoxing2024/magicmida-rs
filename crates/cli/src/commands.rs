//! Command dispatch — maps CLI commands to unpacker functions.

use crate::args::Command;

pub fn run_command(cmd: Command) -> Result<(), anyhow::Error> {
    match cmd {
        Command::Unpack {
            input,
            output,
            create_data_sections,
            shrink,
            oep_policy,
            container_restore,
            profile,
            verbose: _,
        } => crate::unpacker::unpack(
            &input,
            output.as_deref(),
            create_data_sections,
            shrink,
            oep_policy,
            container_restore,
            profile,
        ),
        Command::GenericUnpack {
            input,
            output,
            wait_sec,
            stable,
            gate_profile,
            verbose: _,
        } => crate::unpacker::generic_unpack(
            &input,
            output.as_deref(),
            wait_sec,
            stable,
            gate_profile,
        ),
        Command::DumpProcess { pid, unpacked_file } => {
            crate::unpacker::dump_process_code(pid, &unpacked_file)
        }
        Command::Verify {
            unpacked,
            reference,
        } => crate::unpacker::verify_unpacked(&unpacked, &reference),
        Command::Help | Command::Version => {
            unreachable!("Help and Version commands should be handled before run_command")
        }
    }
}
