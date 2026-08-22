/* WO-1901 fixture -- probe TLS shared storage contract (C, MSVC x64).
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
    uint32_t flags;     /* +0x0C mark bits: 1=guard, 2=av, 0x80000000=unknown */
    uint64_t token_va;  /* +0x10 */
    uint64_t unknown_code; /* +0x18 */
} MidaProbeTls;         /* 0x20 */

#define MIDA_TLS_MARK_GUARD   0x00000001u
#define MIDA_TLS_MARK_AV      0x00000002u
#define MIDA_TLS_MARK_UNKNOWN 0x80000000u

_Static_assert(sizeof(MidaProbeTls) == 0x20, "MidaProbeTls size");
_Static_assert(offsetof(MidaProbeTls, magic) == 0x00, "magic offset");
_Static_assert(offsetof(MidaProbeTls, active) == 0x04, "active offset");
_Static_assert(offsetof(MidaProbeTls, seq) == 0x08, "seq offset");
_Static_assert(offsetof(MidaProbeTls, token_va) == 0x10, "token_va offset");
_Static_assert(offsetof(MidaProbeTls, unknown_code) == 0x18, "unknown_code offset");

/* Reference implementation of the filter-side classification (pure logic).
 * Returns:
 *   0 = ATTR_OK (not our probe fault -> walker VEH CONTINUE_SEARCH)
 *   1 = ATTR_FAULT: guard/AV at token_va or token_va+8
 *   2 = ATTR_ABORT: anything else (unknown code, address mismatch, inactive,
 *       bad magic, zero token, overflow)
 * This is the FILTER/VEH path: it only runs while a probe is in flight
 * (active==1); active==0 is an immediate ABORT and the stale-mark check
 * does NOT belong here (it would be unreachable). Stale detection lives in
 * the begin-side pre-write check mida_tls_begin_check below (WO-2101 sec.4.4a/b).
 */
enum { ATTR_OK = 0, ATTR_FAULT = 1, ATTR_ABORT = 2 };

typedef struct AttrInput {
    uint32_t code;            /* ExceptionCode */
    uint64_t access_addr;     /* ExceptionInformation[1] */
    uint64_t token_va;        /* TLS slot value */
    uint32_t active;          /* TLS slot value */
    uint32_t magic;           /* TLS slot value */
    uint32_t flags;           /* TLS slot value (begin-side stale check) */
    uint32_t seq;             /* TLS slot value */
    uint32_t expected_seq;    /* caller-side expected seq (WO-2101 sec.4.4b) */
    int      seq_checked;     /* 1 = compare seq, 0 = skip (filter path) */
} AttrInput;

static uint32_t mida_attr_classify(AttrInput in) {
    if (in.magic != MIDA_TLS_MAGIC) return ATTR_ABORT;
    if (in.active == 0) return ATTR_ABORT;   /* inactive -> not our probe fault */
    if (in.token_va == 0) return ATTR_ABORT;
    if (in.token_va > (uint64_t)-8) return ATTR_ABORT; /* va+8 overflow */
    if (in.access_addr != in.token_va &&
        in.access_addr != in.token_va + 8) return ATTR_ABORT;
    if (in.code != 0x80000001u && in.code != 0xC0000005u) return ATTR_ABORT;
    /* seq closure (main-path check, not filter): expected_seq mismatch
     * means re-entry or a late exception from an earlier candidate. */
    if (in.seq_checked && in.seq != in.expected_seq) return ATTR_ABORT;
    return ATTR_FAULT;
}

/* Begin-side pre-write stale detection (WO-2201 sec.4.4a/sec.4.4b) -- the REACHABLE
 * stale check. Runs inside mida_probe_tls_begin BEFORE any field is written:
 *   - slot corrupted  (magic != 0 && magic != MIDA_TLS_MAGIC) -> ABORT
 *   - re-entry        (active != 0)                           -> ABORT
 *   - stale marks     (active == 0 && (flags != 0 ||
 *                       unknown_code != 0))                   -> ABORT (fail-closed)
 *   - stale token     (active == 0 && token_va != 0)          -> ABORT (fail-closed)
 *     WO-2201: a previous candidate that faulted out with a partially failed
 *     clear (e.g. exception path skipped clear, or clear wrote flags/unknown_code
 *     to zero but token_va survived) must NOT be silently overwritten. Without
 *     this check the next begin would accept the old token and lose the
 *     fail-closed guarantee (stale token could be attributed to the new probe).
 *     token_va must be 0 before begin writes the new candidate token.
 * Only when this returns ATTR_OK does begin write
 * magic/active=1/flags=0/unknown_code=0/token_va/seq.
 */
static uint32_t mida_tls_begin_check(uint32_t magic, uint32_t active,
                                     uint32_t flags, uint64_t unknown_code,
                                     uint64_t token_va) {
    if (magic != 0 && magic != MIDA_TLS_MAGIC) return ATTR_ABORT; /* corrupted */
    if (active != 0) return ATTR_ABORT;                            /* re-entry */
    if (flags != 0 || unknown_code != 0) return ATTR_ABORT;        /* stale mark */
    if (token_va != 0) return ATTR_ABORT;                          /* stale token */
    return ATTR_OK;
}

/* State-transition fixture rows (WO-1702 sec.4.2 rows 1-8, mapped to inputs):
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