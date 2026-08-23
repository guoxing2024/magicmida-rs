/* WO-2501 fixture -- 7-arg thunk RUNTIME contract (local x64 verified).
 * DESIGN FIXTURE + local runtime evidence; not a production implementation.
 *
 * Three independent checks (thunk7_v2_test, LOCAL x64 on worker machine;
 * NOT remote target, NOT Windows live, NOT LIVE-4):
 *   1) arg pass-through : slot[0..6] == thunk args arg0..arg6 (all intact)
 *   2) callee ENTRY     : rsp mod 16 == 8, recorded by asm stub BEFORE any
 *                         prologue (no _AddressOfReturnAddress interference)
 *   3) call pre-rsp     : thunk writes rsp to args+0x48 with the verified
 *                         opcode 49 89 63 48 (mov [r11+0x48], rsp)
 *                         -> mod 16 == 0
 * Evidence: D:\Temp\thunk7_v2_stdout.txt (THUNK7 COMBINED PASS, EXIT=0),
 * hashes in AUDIT_EVIDENCE_BATCH24_20260823.md.
 */
#ifndef WO2501_THUNK7_RUNTIME_CONTRACT_H
#define WO2501_THUNK7_RUNTIME_CONTRACT_H

#include <stdint.h>
#include <stddef.h>

/* ---- Correct rsp-probe opcode (WO-2501, ml64/dumpbin verified) ----
 *  49 89 63 48   =  mov qword ptr [r11+48h], rsp
 *  (REX.W=1,B=0 -> SIB-free ModRM 63: mod=01, reg=100(rsp), rm=011(r11))
 *
 * WRONG opcode (WO-2401 used it): 4D 89 63 48 = mov [r11+48h], r12
 *  (REX.WRB R=1 selects r12).  MUST NOT be used for an rsp probe.
 */
#define THUNK7_RSP_PROBE_OPCODE_0 0x49u
#define THUNK7_RSP_PROBE_OPCODE_1 0x89u
#define THUNK7_RSP_PROBE_OPCODE_2 0x63u
#define THUNK7_RSP_PROBE_OPCODE_3 0x48u

/* ---- ThunkArgs7 with rsp probe slot (0x50 bytes) ---- */
typedef struct ThunkArgs7Probe {
    uint64_t fn_ptr;      /* +0x00 */
    uint64_t arg0;        /* +0x08 */
    uint64_t arg1;        /* +0x10 */
    uint64_t arg2;        /* +0x18 */
    uint64_t arg3;        /* +0x20 */
    uint64_t arg4;        /* +0x28 */
    uint64_t arg5;        /* +0x30 */
    uint64_t arg6;        /* +0x38 */
    uint64_t reserved;    /* +0x40 */
    uint64_t rsp_probe;   /* +0x48 written by thunk (49 89 63 48) */
} ThunkArgs7Probe;         /* 0x50 */

_Static_assert(sizeof(ThunkArgs7Probe) == 0x50, "probe args size");
_Static_assert(offsetof(ThunkArgs7Probe, rsp_probe) == 0x48, "probe offset");

/* ---- Entry-alignment measurement contract (WO-2501) ----
 * The callee entry rsp MUST be measured by an assembly stub that records
 * rsp as its FIRST instruction (before any push/sub). C-level tricks like
 * _AddressOfReturnAddress() are invalid because compiler prologues (e.g.
 * sub rsp,0x18) change rsp before the measurement point.
 *
 * Stub pattern (ml64):
 *   callee7_entry PROC
 *       mov   rax, rsp              ; entry rsp
 *       and   rax, 0Fh
 *       mov   r10, QWORD PTR [g_slot]
 *       mov   QWORD PTR [r10+56], rax  ; slot[7] = entry rsp mod 16
 *       ... record args ...
 *       ret
 *   callee7_entry ENDP
 * Expected: slot[7] == 8 (entry rsp mod 16, ABI).
 */

/* ---- Unified mapping (frozen) ---- */
/* blob offset -> delivery:
 *   +0x00 fn_ptr -> rax -> call rax
 *   +0x08 arg0   -> rcx
 *   +0x10 arg1   -> rdx
 *   +0x18 arg2   -> r8
 *   +0x20 arg3   -> r9
 *   +0x28 arg4   -> [rsp+0x20] (5th param, outgoing)
 *   +0x30 arg5   -> [rsp+0x28] (6th param, outgoing)
 *   +0x38 arg6   -> [rsp+0x30] (7th param, outgoing)
 * frame: sub rsp,0x38 (56 = 8 mod 16) aligns call pre-rsp to 0 mod 16;
 * shadow space = rsp+0x00..0x1F (32 B, callee-owned).
 */

#endif /* WO2501_THUNK7_RUNTIME_CONTRACT_H */