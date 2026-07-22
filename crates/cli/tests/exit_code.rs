//! Integration test: CLI exit-code mapping and help/usage surface.
//!
//! No real sample is executed and no network is used — this only exercises
//! the pure [`mida_cli::exit_code_for_error`] mapping and the help text.

use mida_cli::{exit_code_for_error, unpacker::GenericGateFailure, EXIT_FATAL, EXIT_GATE_FAILURE};

#[test]
fn plain_error_exits_1() {
    #[derive(Debug, thiserror::Error)]
    #[error("boom")]
    struct Boom;
    assert_eq!(exit_code_for_error(&Boom), EXIT_FATAL);
}

#[test]
fn gate_failure_exits_2() {
    let gf = GenericGateFailure {
        failures: vec![".text section missing"],
    };
    assert_eq!(exit_code_for_error(&gf), EXIT_GATE_FAILURE);
}

#[test]
fn anyhow_wrapped_gate_failure_exits_2() {
    let gf = GenericGateFailure {
        failures: vec![".text section has no raw data"],
    };
    let e: anyhow::Error = anyhow::Error::from(gf);
    assert_eq!(exit_code_for_error(e.as_ref()), EXIT_GATE_FAILURE);
}

#[test]
fn help_text_documents_gate_profile_option() {
    // Render help by invoking the built CLI binary.  A failure to spawn the
    // binary, or a non-zero exit status, MUST fail the test (no silent skip),
    // and diagnostics must include stdout + stderr so failures are debuggable.
    let bin = env!("CARGO_BIN_EXE_mida-cli");
    let out = std::process::Command::new(bin)
        .arg("--help")
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {bin} --help: {e}"));

    assert!(
        out.status.success(),
        "`{} --help` exited non-zero (status={});\n--- stdout ---\n{}\n--- stderr ---\n{}",
        bin,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--gate-profile"),
        "help must document --gate-profile; got:\n{stdout}"
    );
    assert!(
        stdout.contains("packer-agnostic"),
        "missing packer-agnostic in help"
    );
    assert!(
        stdout.contains("ahk-launcher"),
        "missing ahk-launcher in help"
    );
}
