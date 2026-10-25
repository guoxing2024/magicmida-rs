//! Tests for anti-anti-debug constants and helpers.

use super::*;

// ---------------------------------------------------------------------------
// ScyllaHide profile selection
// ---------------------------------------------------------------------------

const SAMPLE_INI: &str = "[SETTINGS]\nCurrentProfile=Magicmida\n\
                          [Magicmida]\nNtCloseHook=0\nWindowTitle=Themida\n";

#[test]
fn replace_current_profile_rewrites_only_that_line() {
    let out = replace_current_profile(SAMPLE_INI, "VMProtect x86/x64").expect("has a profile key");
    assert!(out.contains("CurrentProfile=VMProtect x86/x64\n"));
    assert!(!out.contains("CurrentProfile=Magicmida"));
    // Everything else survives byte for byte, so a hand-edited profile file
    // keeps its edits.
    assert!(out.contains("[Magicmida]\nNtCloseHook=0\nWindowTitle=Themida\n"));
    assert_eq!(out.lines().count(), SAMPLE_INI.lines().count());
}

#[test]
fn replace_current_profile_preserves_line_terminators() {
    // CRLF must not be silently converted: the injector ships a Windows-style
    // file and rewriting it to LF would be an unrelated change.
    let crlf = "[SETTINGS]\r\nCurrentProfile=Magicmida\r\n[A]\r\nK=1\r\n";
    let out = replace_current_profile(crlf, "Other").unwrap();
    assert_eq!(out, "[SETTINGS]\r\nCurrentProfile=Other\r\n[A]\r\nK=1\r\n");
    assert_eq!(out.matches("\r\n").count(), 4);

    // A file with no trailing newline keeps not having one.
    let bare = "[SETTINGS]\nCurrentProfile=X";
    assert_eq!(
        replace_current_profile(bare, "Y").unwrap(),
        "[SETTINGS]\nCurrentProfile=Y"
    );
}

#[test]
fn replace_current_profile_is_case_and_indent_tolerant_but_absent_safe() {
    assert!(replace_current_profile("[SETTINGS]\n  currentprofile = A\n", "B")
        .unwrap()
        .contains("CurrentProfile=B"));
    // No profile key at all: `None`, never an unchanged string, so
    // `select_profile` can refuse instead of injecting with the wrong profile.
    assert_eq!(replace_current_profile("[SETTINGS]\n[A]\nK=1\n", "B"), None);
    assert_eq!(replace_current_profile("", "B"), None);
}

#[test]
fn replace_current_profile_is_idempotent_for_the_same_profile() {
    let once = replace_current_profile(SAMPLE_INI, "Other").unwrap();
    let twice = replace_current_profile(&once, "Other").unwrap();
    assert_eq!(once, twice);
}

#[test]
fn ptr_from_bytes_x86() {
    let bytes = [0x78, 0x56, 0x34, 0x12];
    let addr = ptr_from_bytes(&bytes);
    assert_eq!(addr, 0x1234_5678);
}

#[test]
#[cfg(target_pointer_width = "64")]
fn ptr_from_bytes_x64() {
    // Only meaningful on a 64-bit host: `ptr_from_bytes` returns `usize`, so on
    // i686 the 8-byte read is truncated to 32 bits and the expectation below
    // would be wrong (and, before this gate, the literal itself did not even
    // compile: "literal out of range for `usize`").
    let bytes = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
    let addr = ptr_from_bytes(&bytes);
    assert_eq!(addr, 0x0123_4567_89AB_CDEF);
}

#[test]
fn ptr_from_bytes_partial() {
    // Only 4 bytes provided — treated as u32.
    let bytes = [0xEF, 0xBE, 0xAD, 0xDE];
    let addr = ptr_from_bytes(&bytes);
    assert_eq!(addr, 0xDEAD_BEEF_u32 as usize);
}

#[test]
fn constants_are_correct() {
    // Only the constants that survive on the live path are asserted here.
    // PROCESS_DEBUG_PORT / _OBJECT_HANDLE / _FLAGS / STATUS_PORT_NOT_SET were
    // removed with NtQueryInformationProcess handling (no call sites).
    assert_eq!(THREAD_HIDE_FROM_DEBUGGER, 0x11);
    assert_eq!(STATUS_SUCCESS, 0);
}

#[test]
#[cfg(target_arch = "x86")]
fn nt_qip_syscall_fallback_is_sensible() {
    assert_eq!(NT_QIP_SYSCALL_NUMBER, 0x16);
}
