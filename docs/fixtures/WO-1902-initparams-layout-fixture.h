/* WO-1902 fixture — MidaInitParams v1/v2 byte layout contract.
 * DESIGN FIXTURE for offline review; not a compiled implementation.
 * Layout must match crates/cli/src/unpacker/runtime_loader.rs
 * build_init_params_bytes (v1, 0x30) and the WO-1505 §5.3a frozen v2
 * extension (0x48).
 */
#ifndef WO1902_LAYOUT_FIXTURE_H
#define WO1902_LAYOUT_FIXTURE_H

#include <stdint.h>
#include <stddef.h>

/* MIDA2P2\0 as LE u64: bytes 4D 49 44 41 32 50 32 00 */
#define MIDA_INIT_PARAMS_V2_MAGIC 0x003250324144494DuLL

typedef struct MidaInitParams {
    uint32_t target_pid;              /* 0x00 */
    uint32_t _pad0;                   /* 0x04 */
    uint64_t module_base;             /* 0x08 */
    const char* profile_id;           /* 0x10 */
    const char* profile_digest;       /* 0x18 */
    uint64_t expected_hooks;          /* 0x20 */
    const char* const* expected_surfaces; /* 0x28 */
} MidaInitParams;                     /* 0x30 */

typedef struct MidaInitParamsV2 {
    MidaInitParams v1;                /* 0x00..0x30 (bit-identical) */
    uint64_t magic_v2;                /* 0x30 */
    const char* expected_runtime_sha256; /* 0x38 */
    uint64_t expected_runtime_sha256_len; /* 0x40 */
} MidaInitParamsV2;                   /* 0x48 */

_Static_assert(sizeof(MidaInitParams) == 0x30, "v1 size 0x30");
_Static_assert(sizeof(MidaInitParamsV2) == 0x48, "v2 size 0x48");
_Static_assert(offsetof(MidaInitParams, target_pid) == 0x00, "v1 target_pid");
_Static_assert(offsetof(MidaInitParams, module_base) == 0x08, "v1 module_base");
_Static_assert(offsetof(MidaInitParams, profile_id) == 0x10, "v1 profile_id");
_Static_assert(offsetof(MidaInitParams, profile_digest) == 0x18, "v1 profile_digest");
_Static_assert(offsetof(MidaInitParams, expected_hooks) == 0x20, "v1 expected_hooks");
_Static_assert(offsetof(MidaInitParams, expected_surfaces) == 0x28, "v1 expected_surfaces");
_Static_assert(offsetof(MidaInitParamsV2, magic_v2) == 0x30, "v2 magic_v2");
_Static_assert(offsetof(MidaInitParamsV2, expected_runtime_sha256) == 0x38, "v2 digest ptr");
_Static_assert(offsetof(MidaInitParamsV2, expected_runtime_sha256_len) == 0x40, "v2 digest len");

/* Golden bytes (see WO-1505 §5.3a):
 * v1 with target_pid=0x11223344, module_base=0x400000,
 *     profile_id=0x401000, profile_digest=0x402000,
 *     expected_hooks=2, expected_surfaces=0x403000:
 *   44 33 22 11 00 00 00 00 | 00 00 40 00 00 00 00 00
 *   00 10 40 00 00 00 00 00 | 00 20 40 00 00 00 00 00
 *   02 00 00 00 00 00 00 00 | 00 30 40 00 00 00 00 00
 * v2 extension with magic=0x003250324144494D, digest=0x404000, len=64:
 *   4D 49 44 41 32 50 32 00 | 00 40 40 00 00 00 00 00
 *   40 00 00 00 00 00 00 00
 */
static const unsigned char WO1902_V1_GOLDEN[0x30] = {
    0x44,0x33,0x22,0x11, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x40,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x10,0x40,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x20,0x40,0x00, 0x00,0x00,0x00,0x00,
    0x02,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x30,0x40,0x00, 0x00,0x00,0x00,0x00,
};
static const unsigned char WO1902_V2_EXT_GOLDEN[0x18] = {
    0x4D,0x49,0x44,0x41, 0x32,0x50,0x32,0x00,
    0x00,0x40,0x40,0x00, 0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
};

#endif /* WO1902_LAYOUT_FIXTURE_H */
