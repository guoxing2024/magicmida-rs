/* WO-1901 fixture — probe TLS shared storage contract (C, MSVC x64).
 * This is a DESIGN FIXTURE for offline review; it is NOT a compiled
 * implementation and does NOT prove Windows behaviour.
 */
#ifndef WO1901_FIXTURE_H
#define WO1901_FIXTURE_H

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#define MIDA_TLS_MAGIC 0x4D504354u /* "MPCT" LE */

typedef struct MidaProbeTls {
    uint32_t magic;     /* +0x00 */
    uint32_t active;    /* +0x04 */
    uint32_t seq;       /* +0x08 */
    uint32_t reserved;  /* +0x0C must be 0 */
    uint64_t token_va;  /* +0x10 */
} MidaProbeTls;         /* 0x18 */

_Static_assert(sizeof(MidaProbeTls) == 0x18, "MidaProbeTls size");
_Static_assert(offsetof(MidaProbeTls, magic) == 0x00, "magic offset");
_Static_assert(offsetof(MidaProbeTls, active) == 0x04, "active offset");
_Static_assert(offsetof(MidaProbeTls, seq) == 0x08, "seq offset");
_Static_assert(offsetof(MidaProbeTls, token_va) == 0x10, "token_va offset");

/* Reference implementation of the filter-side classification (pure logic).
 * Returns:
 *   0 = MIDA_PROBE_OK-equivalent (no fault, not used by filter)
 *   1 = FAULT: guard/AV at token_va or token_va+8
 *   2 = ABORT: anything else (unknown code, address mismatch, inactive,
 *       bad magic, zero token, overflow)
 */
enum { ATTR_OK = 0, ATTR_FAULT = 1, ATTR_ABORT = 2 };

typedef struct AttrInput {
    uint32_t code;            /* ExceptionCode */
    uint64_t access_addr;     /* ExceptionInformation[1] */
    uint64_t token_va;        /* TLS slot value */
    uint32_t active;          /* TLS slot value */
    uint32_t magic;           /* TLS slot value */
} AttrInput;

static uint32_t mida_attr_classify(AttrInput in) {
    if (in.magic != MIDA_TLS_MAGIC) return ATTR_ABORT;
    if (in.active == 0) return ATTR_ABORT;
    if (in.token_va == 0) return ATTR_ABORT;
    if (in.token_va > (uint64_t)-8) return ATTR_ABORT; /* va+8 overflow */
    if (in.access_addr != in.token_va &&
        in.access_addr != in.token_va + 8) return ATTR_ABORT;
    if (in.code != 0x80000001u && in.code != 0xC0000005u) return ATTR_ABORT;
    return ATTR_FAULT;
}

/* State-transition fixture rows (WO-1702 §4.2 rows 1-8, mapped to inputs):
 * Row1: guard, protector decrypts        -> VEH guard_seen=1, status OK -> Type B
 * Row2: guard, protector misses          -> FAULT                        -> Type A(guard)
 * Row3: AV, protector decrypts           -> VEH av_seen=1, status OK     -> Type C(+AV)
 * Row4: AV, protector misses             -> FAULT                        -> Type A
 * Row5: unknown code                     -> ABORT                        -> walker abort
 * Row6: unknown code + protector CE      -> ABORT (unknown_code!=0)      -> walker abort
 * Row7: non-probe thread/addr mismatch   -> VEH not observe / ABORT      -> unrelated
 * Row8: probe fault, VEH not called      -> unobserved + OK/FAULT        -> Type C or FAULT
 * (the fixture asserts mida_attr_classify outputs for rows 2/4/5/7 in tests)
 */

#endif /* WO1901_FIXTURE_H */
