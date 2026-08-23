/* WO-2301 fixture -- 7-arg thunk machine-code / stack ABI contract.
 * DESIGN FIXTURE for offline review; not a compiled implementation.
 * Byte table verified with ml64 + dumpbin (MSVC x64, 2026-08-23 worker run).
 * Aligned with the existing 6-arg thunk (runtime_loader.rs THUNK_CODE):
 *   mov r11,rcx = 49 89 CB; indirect call = call rax (FF D0);
 *   self-built frame via sub/add rsp.
 */
#ifndef WO2301_THUNK7_FIXTURE_H
#define WO2301_THUNK7_FIXTURE_H

#include <stdint.h>
#include <stddef.h>

/* ---- THUNK_CODE_7ARG: 60 bytes (0x3C), ml64/dumpbin verified ---- */
#define THUNK7_CODE_SIZE 60u

static const unsigned char THUNK7_CODE[THUNK7_CODE_SIZE] = {
    0x49, 0x89, 0xCB,                /* 0000 mov r11, rcx */
    0x49, 0x8B, 0x03,                /* 0003 mov rax, [r11]      fn_ptr */
    0x49, 0x8B, 0x4B, 0x08,          /* 0006 mov rcx, [r11+8]    arg0 */
    0x49, 0x8B, 0x53, 0x10,          /* 000A mov rdx, [r11+16]   arg1 */
    0x4D, 0x8B, 0x43, 0x18,          /* 000E mov r8,  [r11+24]   arg2 */
    0x4D, 0x8B, 0x4B, 0x20,          /* 0012 mov r9,  [r11+32]   arg3 */
    0x48, 0x83, 0xEC, 0x40,          /* 0016 sub rsp, 0x40       frame */
    0x4D, 0x8B, 0x53, 0x28,          /* 001A mov r10, [r11+40]   arg4 */
    0x4C, 0x89, 0x54, 0x24, 0x28,    /* 001E mov [rsp+0x28], r10 home5 */
    0x4D, 0x8B, 0x53, 0x30,          /* 0023 mov r10, [r11+48]   arg5 */
    0x4C, 0x89, 0x54, 0x24, 0x30,    /* 0027 mov [rsp+0x30], r10 home6 */
    0x4D, 0x8B, 0x53, 0x38,          /* 002C mov r10, [r11+56]   arg6 */
    0x4C, 0x89, 0x54, 0x24, 0x38,    /* 0030 mov [rsp+0x38], r10 home7 */
    0xFF, 0xD0,                      /* 0035 call rax */
    0x48, 0x83, 0xC4, 0x40,          /* 0037 add rsp, 0x40 */
    0xC3,                            /* 003B ret */
};

_Static_assert(sizeof(THUNK7_CODE) == THUNK7_CODE_SIZE, "thunk7 size 60");

/* Instruction boundary offsets (0-based, verified by dumpbin):
 * 0x00 mov r11,rcx (3)
 * 0x03 mov rax,[r11] (3)
 * 0x06 mov rcx,[r11+8] (4)
 * 0x0A mov rdx,[r11+16] (4)
 * 0x0E mov r8,[r11+24] (4)
 * 0x12 mov r9,[r11+32] (4)
 * 0x16 sub rsp,0x40 (4)
 * 0x1A mov r10,[r11+40] (4)
 * 0x1E mov [rsp+0x28],r10 (5)
 * 0x23 mov r10,[r11+48] (4)
 * 0x27 mov [rsp+0x30],r10 (5)
 * 0x2C mov r10,[r11+56] (4)
 * 0x30 mov [rsp+0x38],r10 (5)
 * 0x35 call rax (2)
 * 0x37 add rsp,0x40 (4)
 * 0x3B ret (1)
 */

/* ---- ThunkArgs7: 9 slots x 8 bytes = 72 bytes (0x48) ---- */
typedef struct ThunkArgs7 {
    uint64_t fn_ptr;      /* +0x00 module_base + MidaAntidebugInitializeV2 RVA */
    uint64_t arg0;        /* +0x08 params_v2_blob_va */
    uint64_t arg1;        /* +0x10 params_bytes */
    uint64_t arg2;        /* +0x18 out_runtime_sha256_va */
    uint64_t arg3;        /* +0x20 64 (out_runtime_sha256_len) */
    uint64_t arg4;        /* +0x28 out_attestation_json_va */
    uint64_t arg5;        /* +0x30 ATTESTATION_BUFFER_SIZE */
    uint64_t arg6;        /* +0x38 out_attestation_written_va */
    uint64_t reserved;    /* +0x40 0 */
} ThunkArgs7;              /* 0x48 */

_Static_assert(sizeof(ThunkArgs7) == 0x48, "ThunkArgs7 size 0x48");
_Static_assert(offsetof(ThunkArgs7, fn_ptr) == 0x00, "fn_ptr");
_Static_assert(offsetof(ThunkArgs7, arg0) == 0x08, "arg0");
_Static_assert(offsetof(ThunkArgs7, arg1) == 0x10, "arg1");
_Static_assert(offsetof(ThunkArgs7, arg2) == 0x18, "arg2");
_Static_assert(offsetof(ThunkArgs7, arg3) == 0x20, "arg3");
_Static_assert(offsetof(ThunkArgs7, arg4) == 0x28, "arg4");
_Static_assert(offsetof(ThunkArgs7, arg5) == 0x30, "arg5");
_Static_assert(offsetof(ThunkArgs7, arg6) == 0x38, "arg6");
_Static_assert(offsetof(ThunkArgs7, reserved) == 0x40, "reserved");

/* Stack home offsets (relative to rsp AFTER sub rsp,0x40):
 *   arg4 home = rsp+0x28 (5th param)
 *   arg5 home = rsp+0x30 (6th param)
 *   arg6 home = rsp+0x38 (7th param)
 *   shadow space = rsp+0x00..0x1F (32 bytes for the callee)
 *   rsp+0x20 unused (8-byte alignment gap)
 * Frame size 0x40 = 32 shadow + 24 homes + 8 pad; 16-aligned.
 */
#define THUNK7_FRAME_SIZE     0x40u
#define THUNK7_HOME_ARG4      0x28u
#define THUNK7_HOME_ARG5      0x30u
#define THUNK7_HOME_ARG6      0x38u

#endif /* WO2301_THUNK7_FIXTURE_H */