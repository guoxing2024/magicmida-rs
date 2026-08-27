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
    /// Updated 2026-08-27 from the official ScyllaHide v1.4 release
    /// (2023-03-24_13-03.zip, github.com/x64dbg/ScyllaHide) — the same
    /// release whose HookLibraryx64.dll matches the previously trusted
    /// hash. HookLibrary hash unchanged.
    pub const INJECTOR_CLI_X64: &str =
        "b902d5cef490831c13ee78cde135fe530ae43bb20c687dec4f222ec83f75dbd0";
    /// `HookLibraryx64.dll` (SHA-256).
    pub const HOOK_LIBRARY_X64: &str =
        "d4b20eed23caebad7efa53e5f2f3c86d445864c2d3e43b343e01c8a9785e800e";
}

/// Known-good SHA-256 hashes for the x86 ScyllaHide helpers.
///
/// **Residual (2026-07-24):** no trusted `InjectorCLIx86.exe` /
/// `HookLibraryx86.dll` were present on the audit host
/// (`D:\magicmida-rs-build` ships x64 only). Placeholders remain so an
/// accidental x86 build fails closed on inject rather than silently
/// trusting unknown bits. When trusted x86 helpers land, replace both
/// hex digests and record vault hygiene under
/// `D:\MidaVault\lab\evidence\hygiene\`.
#[cfg(target_arch = "x86")]
mod known_hashes {
    /// `InjectorCLIx86.exe` (SHA-256) — placeholder; fail-closed until filled.
    pub const INJECTOR_CLI_X86: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    /// `HookLibraryx86.dll` (SHA-256) — placeholder; fail-closed until filled.
    pub const HOOK_LIBRARY_X86: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
}

/// Returns the expected hash for the matching injector binary based on the
/// target architecture.
#[cfg(target_arch = "x86_64")]
pub fn expected_injector_hash() -> &'static str {
    known_hashes::INJECTOR_CLI_X64
}

#[cfg(target_arch = "x86")]
pub fn expected_injector_hash() -> &'static str {
    known_hashes::INJECTOR_CLI_X86
}

/// Returns the expected hash for the matching hook-library DLL based on the
/// target architecture.
#[cfg(target_arch = "x86_64")]
pub fn expected_hook_hash() -> &'static str {
    known_hashes::HOOK_LIBRARY_X64
}

#[cfg(target_arch = "x86")]
pub fn expected_hook_hash() -> &'static str {
    known_hashes::HOOK_LIBRARY_X86
}
