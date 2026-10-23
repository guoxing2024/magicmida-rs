//! Tests for anti-anti-debug constants and helpers.

use super::*;

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
    assert_eq!(NtQIP_SYSCALL_NUMBER, 0x16);
}
