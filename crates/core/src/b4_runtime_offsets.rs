// Auto-generated from b4_runtime_offset_map.json (exact runtime binding).
// DO NOT EDIT BY HAND. Regenerate from the offset map (ADR7-B4-RUNTIME-BINDING-CORRECTION-1).
//
// Bound runtime artifact:
//   mida_antidebug_runtime.dll
//   sha256  AE42901EC940DFA95566DCF9E0787D1E2C9439D90E7C593ED3A803A4F9CDBB76
//   size    370,688 B
//   pdb     sha256 B8165CF81B7E5469979FB61E7FE6B84E7376C14A09AF5FA9131DAE4DD86EED96
//           guid    DDCD43FD-2CFF-4242-85BF-39DC0ADB09E0 age 1
// The observer fails closed when the runtime actually loaded does not match
// this sha256: no observation point is installed, no int29 match is claimed.
pub const RUNTIME_SHA256: &str = "AE42901EC940DFA95566DCF9E0787D1E2C9439D90E7C593ED3A803A4F9CDBB76";
pub const RUNTIME_SIZE_BYTES: u64 = 370688;
pub const PDB_SHA256: &str = "B8165CF81B7E5469979FB61E7FE6B84E7376C14A09AF5FA9131DAE4DD86EED96";
pub const PDB_GUID: &str = "DDCD43FD-2CFF-4242-85BF-39DC0ADB09E0";
pub const PDB_AGE: u32 = 1;

/// Observation points (RVA, label) for the bound runtime, slot order 0..3.
pub const OBS_POINTS: [(u32, &str); 4] = [
    (0x2eda0, "panic_count::increase entry"),
    (0x2edc6, "panic_count::increase+0x26 (TLS check jne)"),
    (0x2e604, "panic_with_hook entry"),
    (
        0x2e638,
        "panic_with_hook -> panic_count::increase call site",
    ),
];

/// int29 (__fastfail) sites for the bound runtime (all `CD 29`).
pub const INT29_SITES: [u32; 9] = [
    0x2bfc1, 0x2c366, 0x2c599, 0x2c759, 0x2d070, 0x2e7e8, 0x2e816, 0x3f32c, 0x3fab7,
];

/// Observed fault RVA recorded by the live matrix against this exact runtime.
pub const OBSERVED_FAULT_RVA: u32 = 0x2e816;
