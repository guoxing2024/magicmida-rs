//! Magicmida-RS — unpacker CLI binary (Themida + generic).
//!
//! Thin wrapper over [`mida_cli::run`]; all logic lives in the library so
//! integration tests can exercise it.

fn main() {
    std::process::exit(i32::from(mida_cli::run()));
}
