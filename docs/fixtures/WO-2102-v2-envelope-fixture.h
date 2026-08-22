/* WO-2102 fixture -- V2 envelope / blob boundary / version negotiation (complete).
 * DESIGN FIXTURE for offline review; not a compiled implementation.
 * Supersedes WO-1902-initparams-layout-fixture.h for the V2 struct and
 * WO-2002-v2-envelope-fixture.h (v1): the V2 struct is the ONLY authoritative
 * 0x48 layout; all reference fields are SELF-RELATIVE OFFSETS and the entry
 * carries an explicit params_bytes (see WO-1505 sec.5.3e/f, WO-2102).
 */
#ifndef WO2102_ENVELOPE_FIXTURE_H
#define WO2102_ENVELOPE_FIXTURE_H

#include <stdint.h>
#include <stddef.h>

#define MIDA_INIT_PARAMS_V2_MAGIC 0x003250324144494DuLL /* "MIDA2P2\0" LE */
#define MIDA_PARAMS_MIN_BYTES 0x48u
#define MIDA_DIGEST_LEN 64u
#define MAX_EXPECTED_HOOKS 256u /* WO-2202 frozen bound */

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
_Static_assert(offsetof(MidaInitParamsV2, profile_digest_off) == 0x18, "profile_digest_off");
_Static_assert(offsetof(MidaInitParamsV2, expected_hooks) == 0x20, "expected_hooks");
_Static_assert(offsetof(MidaInitParamsV2, expected_surfaces_off) == 0x28, "surfaces_off");
_Static_assert(offsetof(MidaInitParamsV2, magic_v2) == 0x30, "magic_v2");
_Static_assert(offsetof(MidaInitParamsV2, digest_off) == 0x38, "digest_off");
_Static_assert(offsetof(MidaInitParamsV2, digest_len) == 0x40, "digest_len");

/* Entry signature (7 args; see WO-1505 sec.5.3c) */
/* int32_t MidaAntidebugInitializeV2(
 *     const MidaInitParamsV2* params,   arg0
 *     uint64_t params_bytes,            arg1
 *     uint8_t* out_runtime_sha256,      arg2
 *     size_t   out_runtime_sha256_len,  arg3
 *     uint8_t* out_attestation_json,    arg4
 *     size_t   out_attestation_len,     arg5
 *     size_t*  out_attestation_written) arg6
 */

/* Envelope validation (pure logic; WO-1505 sec.5.3f/g + WO-2102).
 * Returns 0 = accept, non-zero = reject reason:
 *   1 ShortBlob     (params==NULL || params_bytes < 0x48)
 *   2 MissingMagic  (magic_v2 == 0)
 *   3 UnknownMagic  (magic_v2 != MIDA_INIT_PARAMS_V2_MAGIC)
 *   4 Overflow      (off+need wraps)
 *   5 OutOfBounds   (off+need > params_bytes)
 *   6 InvalidArgument (hook/surface/digest inconsistency)
 *   7 TruncatedDigest / 8 BufferOverrun / 9 BadHex
 *   10 TruncatedString (profile string without NUL within envelope)
 *   11 NonCanonicalVa (surface array entry 0 or non-canonical user VA)
 *   12 ProvenanceReject (params != expected blob_base_va)
 *   13 UnknownExtension (magic ok but undeclared tail bytes)
 *   14 HeaderFault (header read fault -> fail-closed)
 */
typedef struct EnvelopeInput {
    const MidaInitParamsV2* params;
    uint64_t params_bytes;
    const unsigned char* blob;      /* == (const unsigned char*)params; same allocation */
    uint64_t expected_blob_base_va; /* controller-recorded target VA */
    int header_readable;            /* 1 = header 0x48 bytes committed/readable */
} EnvelopeInput;

static uint64_t mida_checked_add(uint64_t a, uint64_t b, int* overflow) {
    *overflow = (b > (uint64_t)-1 - a);
    return a + b;
}

static uint64_t mida_checked_mul(uint64_t a, uint64_t b, int* overflow) {
    /* checked multiplication: overflow if a != 0 && b > UINT64_MAX / a */
    *overflow = (a != 0 && b > (uint64_t)-1 / a);
    return a * b;
}

static int mida_is_canonical_user_va(uint64_t va) {
    /* x64 canonical user VA: 0 < va < 0x0000800000000000 (48-bit user half) */
    return va != 0 && va < 0x0000800000000000ull;
}

static uint32_t mida_v2_envelope_check(EnvelopeInput in) {
    int ovf = 0;
    uint64_t end;
    uint64_t i;   /* WO-2202: iteration width == expected_hooks width */
    if (in.params == 0 || in.params_bytes < MIDA_PARAMS_MIN_BYTES) return 1;
    if (in.blob != (const unsigned char*)in.params) return 12; /* same allocation */
    if (!in.header_readable) return 14;                        /* header fault */
    if (in.params->magic_v2 == 0) return 2;
    if (in.params->magic_v2 != MIDA_INIT_PARAMS_V2_MAGIC) return 3;
    /* params must be the controller-recorded blob base (provenance) */
    if ((uint64_t)(uintptr_t)in.params != in.expected_blob_base_va) return 12;
    /* digest region: off + 65 <= params_bytes (checked) */
    if (in.params->digest_off < MIDA_PARAMS_MIN_BYTES) return 5;
    end = mida_checked_add(in.params->digest_off, 65, &ovf);
    if (ovf) return 4;
    if (end > in.params_bytes) return 5;
    if (in.params->digest_len != MIDA_DIGEST_LEN) return 6;
    /* surfaces: hooks==0 => off must be 0; entries validated per row.
     * WO-2202: expected_hooks is FROZEN to a bounded maximum; iteration uses
     * checked size_t semantics (see MAX_EXPECTED_HOOKS below). */
    if (in.params->expected_hooks > MAX_EXPECTED_HOOKS) return 6;
    if (in.params->expected_hooks == 0 && in.params->expected_surfaces_off != 0) return 6;
    if (in.params->expected_hooks != 0) {
        uint64_t need;
        const uint64_t* entries;
        int ovf2 = 0;
        if (in.params->expected_surfaces_off < MIDA_PARAMS_MIN_BYTES) return 5;
        need = mida_checked_mul((uint64_t)in.params->expected_hooks, 8, &ovf2);
        if (ovf2) return 4;
        end = mida_checked_add(in.params->expected_surfaces_off, need, &ovf2);
        if (ovf2) return 4;
        if (end > in.params_bytes) return 5;
        entries = (const uint64_t*)(in.blob + (size_t)in.params->expected_surfaces_off);
        for (i = 0; i < in.params->expected_hooks; i++) {
            /* each entry is the ONLY explicit absolute-VA exception: a
             * TARGET-LOCAL VA of a surface string inside the same envelope.
             * WO-2202: canonical/nonzero + provenance within the blob +
             * per-entry string NUL scan (bounded by params_bytes). */
            uint64_t sva = entries[i];
            uint64_t soff;
            uint64_t k;
            if (!mida_is_canonical_user_va(sva)) return 11;
            if (sva < in.expected_blob_base_va ||
                sva >= in.expected_blob_base_va + in.params_bytes) return 11;
            soff = sva - in.expected_blob_base_va;
            for (k = 0; k < 65; k++) {
                if (soff + k >= in.params_bytes) return 10;
                if (in.blob[(size_t)(soff + k)] == 0) break;
            }
            if (k >= 65) return 10;
        }
    }
    /* profile_id string: NUL within envelope; bounds checked BEFORE every read
     * (WO-2202: off + i < params_bytes must be proven before p[i]). */
    if (in.params->profile_id_off < MIDA_PARAMS_MIN_BYTES) return 5;
    if (in.params->profile_id_off >= in.params_bytes) return 5;
    {
        uint64_t off = in.params->profile_id_off;
        uint64_t k;
        for (k = 0; k < 65; k++) {
            if (off + k >= in.params_bytes) return 10;
            if (in.blob[(size_t)(off + k)] == 0) break;
        }
        if (k >= 65) return 10;
    }
    /* profile_digest string: same bounds-checked NUL scan */
    if (in.params->profile_digest_off < MIDA_PARAMS_MIN_BYTES) return 5;
    if (in.params->profile_digest_off >= in.params_bytes) return 5;
    {
        uint64_t off = in.params->profile_digest_off;
        uint64_t k;
        for (k = 0; k < 65; k++) {
            if (off + k >= in.params_bytes) return 10;
            if (in.blob[(size_t)(off + k)] == 0) break;
        }
        if (k >= 65) return 10;
    }
    /* digest string scan (within proven 65-byte region): exactly 64 hex + NUL */
    {
        const unsigned char* d = in.blob + (size_t)in.params->digest_off;
        for (i = 0; i < 64; i++) {
            unsigned char c = d[i];
            if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) return 9;
        }
        if (d[64] != 0) return 8;
    }
    /* strict extension rejection (WO-2102): params_bytes must equal the
     * envelope end = digest_off + 65 (no undeclared tail). Any extra bytes
     * beyond the declared segments are an unknown extension -> reject. */
    {
        int ovf3 = 0;
        uint64_t env_end = mida_checked_add(in.params->digest_off, 65, &ovf3);
        if (ovf3) return 4;
        if (in.params_bytes != env_end) return 13;
    }
    return 0; /* accept */
}

#endif /* WO2102_ENVELOPE_FIXTURE_H */
