/* WO-2401 fixture -- 7-arg thunk STACK layout / alignment contract.
 * DESIGN FIXTURE for offline review; not a compiled implementation.
 * Verified by: ml64+dumpbin (bytes) and LOCAL ABI tests
 *   thunk7_final_test.c + thunk7_final_full.asm (fixture-exact bytes):
 * These are LOCAL x64 checks on the worker machine; NOT remote target,
 * NOT Windows live verification, NOT LIVE-4.
 */
#ifndef WO2401_THUNK7_STACK_FIXTURE_H
#define WO2401_THUNK7_STACK_FIXTURE_H

#include <stdint.h>
#include <stddef.h>

/* ---- Stack alignment derivation (WO-2401, frozen) ----
 *
 * Let R = thunk entry rsp (after caller executed `call thunk7`):
 *   R mod 16 == 8        (caller pushed 8-byte return address)
 *
 * thunk executes:
 *   sub rsp, 0x38        -> rsp1 = R - 0x38;  rsp1 mod 16 == 0
 *      (0x38 == 56 == 8 mod 16; 8 - 8 == 0 mod 16)
 *   ... write outgoing args ...
 *   call rax             -> callee entry rsp == rsp1 - 8; mod 16 == 8  (ABI OK)
 *   add rsp, 0x38        -> rsp2 = R
 *   ret
 *
 * Frame layout (relative to rsp1, AFTER sub):
 *   +0x00 .. +0x1F  shadow space (32 B, callee-owned)
 *   +0x20          arg4 (5th param) outgoing
 *   +0x28          arg5 (6th param) outgoing
 *   +0x30          arg6 (7th param) outgoing
 *   +0x38          (end; frame size 0x38)
 *
 * The old WO-2301 layout (sub rsp,0x40; slots +0x28/+0x30/+0x38) was
 * WRONG: 0x40 is a multiple of 16 so call pre-rsp stayed 8 mod 16,
 * misaligning the callee entry. Superseded by this fixture.
 */

#define THUNK7_ENTRY_RSP_MOD16   8u
#define THUNK7_FRAME_SIZE        0x38u   /* 56 = 8 mod 16 -> aligns call */
#define THUNK7_SHADOW_SIZE       0x20u   /* 32 B */
#define THUNK7_OUT_ARG4_OFF      0x20u
#define THUNK7_OUT_ARG5_OFF      0x28u
#define THUNK7_OUT_ARG6_OFF      0x30u

/* Cross-checks (compile-time): frame == shadow + 3*8; frame mod 16 == 8. */
_Static_assert(THUNK7_FRAME_SIZE == THUNK7_SHADOW_SIZE + 0x18u, "frame size");
_Static_assert((THUNK7_FRAME_SIZE % 16u) == 8u, "frame aligns call");
_Static_assert(THUNK7_OUT_ARG6_OFF + 8u <= THUNK7_FRAME_SIZE, "slots in frame");

/* ---- Blob offset -> call-frame mapping (frozen) ---- */
/* ThunkArgs7 (see WO-2301-thunk7-fixture.h):
 *   +0x00 fn_ptr  -> rax (call rax)
 *   +0x08 arg0    -> rcx
 *   +0x10 arg1    -> rdx
 *   +0x18 arg2    -> r8
 *   +0x20 arg3    -> r9
 *   +0x28 arg4    -> [rsp1+0x20]
 *   +0x30 arg5    -> [rsp1+0x28]
 *   +0x38 arg6    -> [rsp1+0x30]
 */
#define THUNK7_BLOB_ARG4_OFF   0x28u
#define THUNK7_BLOB_ARG5_OFF   0x30u
#define THUNK7_BLOB_ARG6_OFF   0x38u

_Static_assert(THUNK7_BLOB_ARG6_OFF + 8u == 0x40u, "blob slot end");


/* ---- rsp-probe opcode (WO-2501 verification note) ----
 * To observe call-pre-rsp in a runtime harness, the thunk must write rsp
 * with the verified encoding:
 *   49 89 63 48   =  mov qword ptr [r11+48h], rsp
 * The previously used 4D 89 63 48 is mov [r11+48h], r12 (REX.R=1) and
 * must NOT be used. See WO-2501-thunk7-runtime-contract.h.
 */
#endif /* WO2401_THUNK7_STACK_FIXTURE_H */