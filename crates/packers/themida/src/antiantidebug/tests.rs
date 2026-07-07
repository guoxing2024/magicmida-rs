//! Tests for anti-anti-debug constants and helpers.

use super::*;

#[test]
fn ptr_from_bytes_x86() {
    let bytes = [0x78, 0x56, 0x34, 0x12];
    let addr = ptr_from_bytes(&bytes);
    assert_eq!(addr, 0x1234_5678);
}

#[test]
fn ptr_from_bytes_x64() {
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
    assert_eq!(THREAD_HIDE_FROM_DEBUGGER, 0x11);
    assert_eq!(PROCESS_DEBUG_PORT, 7);
    assert_eq!(PROCESS_DEBUG_OBJECT_HANDLE, 30);
    assert_eq!(PROCESS_DEBUG_FLAGS, 31);
    assert_eq!(STATUS_SUCCESS, 0);
    assert_eq!(STATUS_PORT_NOT_SET, 0xC000_0353);
}

#[test]
#[cfg(target_arch = "x86")]
fn nt_qip_syscall_fallback_is_sensible() {
    assert_eq!(NtQIP_SYSCALL_NUMBER, 0x16);
}
