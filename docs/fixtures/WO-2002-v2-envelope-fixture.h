/* WO-2002 fixture — V2 envelope / blob boundary / version negotiation.
 * DESIGN FIXTURE for offline review; not a compiled implementation.
 * Supersedes WO-1902-initparams-layout-fixture.h for the V2 struct:
 * all reference fields are SELF-RELATIVE OFFSETS and the entry carries
 * an explicit params_bytes (see WO-1505 §5.3e/f).
 */
#ifndef WO2002_ENVELOPE_FIXTURE_H
#define WO2002_ENVELOPE_FIXTURE_H

#include <stdint.h>
#include <stddef.h>

#define MIDA_INIT_PARAMS_V2_MAGIC 0x003250324144494DuLL /* "MIDA2P2\0" LE */

typedef struct MidaInitParamsV2 {
    uint32_t target_pid;              /* 0x00 */
    uint32_t _pad0;                   /* 0x04 */
    uint64_t module_base;             /* 0x08 */
    uint64_t profile_id_off;          /* 0x10 self-relative */
    uint64_t profile_digest_off;      /* 0x18 self-relative */
    uint64_t expected_hooks;          /* 0x20 */
    uint64_t expected_surfaces_off;   /* 0x28 self-relative (ptr array) */
    uint64_t magic_v2;                /* 0x30 */
    uint64_t digest_off;              /* 0x38 self-relative */
    uint64_t digest_len;              /* 0x40 == 64 */
} MidaInitParamsV2;                   /* 0x48 */

_Static_assert(sizeof(MidaInitParamsV2) == 0x48, "v2 size 0x48");
_Static_assert(offsetof(MidaInitParamsV2, target_pid) == 0x00, "target_pid");
_Static_assert(offsetof(MidaInitParamsV2, module_base) == 0x08, "module_base");
_Static_assert(offsetof(MidaInitParamsV2, profile_id_off) == 0x10, "profile_id_off");
_Static_assert(offsetof(MidaInitParamsV2, expected_surfaces_off) == 0x28, "surfaces_off");
_Static_assert(offsetof(MidaInitParamsV2, magic_v2) == 0x30, "magic_v2");
_Static_assert(offsetof(MidaInitParamsV2, digest_off) == 0x38, "digest_off");
_Static_assert(offsetof(MidaInitParamsV2, digest_len) == 0x40, "digest_len");

/* Entry signature (7 args; see WO-1505 §5.3c) */
/* int32_t MidaAntidebugInitializeV2(
 *     const MidaInitParamsV2* params,   arg0
 *     uint64_t params_bytes,            arg1
 *     uint8_t* out_runtime_sha256,      arg2
 *     size_t   out_runtime_sha256_len,  arg3
 *     uint8_t* out_attestation_json,    arg4
 *     size_t   out_attestation_len,     arg5
 *     size_t*  out_attestation_written) arg6
 */

/* Envelope validation (pure logic; WO-1505 §5.3f/g).
 * Returns 0 = accept, non-zero = reject reason:
 *   1 ShortBlob     (params==NULL || params_bytes < 0x48)
 *   2 MissingMagic  (magic_v2 == 0)
 *   3 UnknownMagic  (magic_v2 != MIDA_INIT_PARAMS_V2_MAGIC)
 *   4 Overflow      (off+need wraps)
 *   5 OutOfBounds   (off+need > params_bytes)
 *   6 InvalidArgument (hook/surface/digest_len inconsistency)
 *   7 TruncatedDigest / 8 BufferOverrun / 9 BadHex
 */
typedef struct EnvelopeInput {
    const MidaInitParamsV2* params;
    uint64_t params_bytes;
    const unsigned char* blob; /* for string scans */
} EnvelopeInput;

static uint32_t mida_v2_envelope_check(EnvelopeInput in) {
    if (in.params == 0 || in.params_bytes < 0x48) return 1; /* ShortBlob */
    if (in.params->magic_v2 == 0) return 2;                 /* MissingMagic */
    if (in.params->magic_v2 != MIDA_INIT_PARAMS_V2_MAGIC) return 3; /* UnknownMagic */
    /* digest region: off + 65 <= params_bytes */
    if (in.params->digest_off < 0x48) return 5;
    if (in.params->digest_off > (uint64_t)-65) return 4;
    if (in.params->digest_off + 65 > in.params_bytes) return 5;
    if (in.params->digest_len != 64) return 6;
    /* surfaces: hooks==0 => off must be 0 */
    if (in.params->expected_hooks == 0 && in.params->expected_surfaces_off != 0) return 6;
    if (in.params->expected_hooks != 0) {
        if (in.params->expected_surfaces_off < 0x48) return 5;
        uint64_t need = (uint64_t)in.params->expected_hooks * 8;
        if (in.params->expected_surfaces_off > (uint64_t)-need) return 4;
        if (in.params->expected_surfaces_off + need > in.params_bytes) return 5;
    }
    /* digest string scan (within proven 65-byte region): exactly 64 hex + NUL */
    {
        const unsigned char* d = in.blob + (size_t)in.params->digest_off;
        for (int i = 0; i < 64; i++) {
            unsigned char c = d[i];
            if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) return 9; /* BadHex (lowercase only) */
        }
        if (d[64] != 0) return 8;   /* BufferOverrun: no NUL at 65th */
        /* NUL before 65th would mean truncated: any of d[0..63]==0 was rejected
         * by the hex check above (0 is not hex), so TruncatedDigest is covered. */
    }
    return 0; /* accept */
}

#endif /* WO2002_ENVELOPE_FIXTURE_H */
