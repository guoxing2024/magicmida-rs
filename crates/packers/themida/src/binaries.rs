//! Known-good SHA-256 hashes for the ScyllaHide helper binaries that ship
//! alongside the Magicmida-RS distribution.
//!
//! The packer crate launches `InjectorCLI{arch}.exe` to inject the
//! `HookLibrary{arch}.dll` anti-anti-debug hook into the debuggee.  These are
//! **external binaries** with full-process injection privileges — a tampered
//! copy could do anything to the debuggee.  We hard-code the expected hashes
//! and verify them before every `Command::spawn` of the injector.
//!
//! ## Adding a new version
//!
//! Run `sha256sum <binary>` over the trusted file and replace the hex below.
//! If the upstream re-releases, bump the expected hash — do **not** comment
//! out the check.

use sha2::{Digest, Sha256};

/// Use the SHA-256 of `bytes` to verify `actual_hex`.
///
/// Returns `true` when the computed hash (lowercased) equals
/// `actual_hex` (case-insensitively).
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let got = format!("{:x}", hasher.finalize());
    got.eq_ignore_ascii_case(expected_hex.trim())
}

/// Known-good SHA-256 hashes for the x64 ScyllaHide helpers.
///
/// Generated from the files committed in the repository root.
#[cfg(target_arch = "x86_64")]
mod known_hashes {
    /// `InjectorCLIx64.exe` (SHA-256).
    pub const INJECTOR_CLI_X64: &str =
        "211f7b804f1db43abddbb3dbdf41162d6cee76ae84e0bb38818cdbf4d07cf630";
    /// `HookLibraryx64.dll` (SHA-256).
    pub const HOOK_LIBRARY_X64: &str =
        "d4b20eed23caebad7efa53e5f2f3c86d445864c2d3e43b343e01c8a9785e800e";
}

/// Known-good SHA-256 hashes for the x86 ScyllaHide helpers.
///
/// **x86 is not supported by this build.** Only the x64 ScyllaHide binaries
/// ship in the repository, so their hashes are known. If you need x86 support,
/// obtain the x86 binaries (`InjectorCLIx86.exe`, `HookLibraryx86.dll`),
/// compute their SHA-256 hashes, and replace the `compile_error!` below with
/// the real hex constants.
#[cfg(target_arch = "x86")]
mod known_hashes {
    // This fires at compile time when targeting x86, because no trusted x86
    // ScyllaHide binaries are shipped and the placeholder hashes were removed
    // for security (a placeholder would silently pass verification if someone
    // tampered with the binary to match the placeholder string).
    compile_error!(
        "x86 ScyllaHide binaries are not shipped. Only x64 is supported. \
         To enable x86, add the real SHA-256 hashes in \
         crates/packers/themida/src/binaries.rs."
    );
}

/// Returns the expected hash for the matching injector binary based on the
/// target architecture.
#[cfg(target_arch = "x86_64")]
pub fn expected_injector_hash() -> &'static str {
    known_hashes::INJECTOR_CLI_X64
}

#[cfg(target_arch = "x86")]
pub fn expected_injector_hash() -> &'static str {
    // x86 is unsupported — known_hashes module contains a compile_error!.
    unreachable!("x86 ScyllaHide binaries are not shipped")
}

/// Returns the expected hash for the matching hook-library DLL based on the
/// target architecture.
#[cfg(target_arch = "x86_64")]
pub fn expected_hook_hash() -> &'static str {
    known_hashes::HOOK_LIBRARY_X64
}

#[cfg(target_arch = "x86")]
pub fn expected_hook_hash() -> &'static str {
    // x86 is unsupported — known_hashes module contains a compile_error!.
    unreachable!("x86 ScyllaHide binaries are not shipped")
}
