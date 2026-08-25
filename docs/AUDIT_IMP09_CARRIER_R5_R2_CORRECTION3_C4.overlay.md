# OVERLAY — CORRECTION-3 is PARTIAL / SUPERSEDED_BY_C4

**Date**: 2026-08-25
**Branch**: codex/imp09-carrier-r5-r2

## Binding

\`\`\`ini
base_head                 = 9cd2e4dffa9c8de3031c78bf8d670688afdd7c78
correction_commits        = 7c0dc8decce897a9a11cce9e1856831dc6e27ca6,
                            f0bd0df706f5636a204744f18e5654bff886620f,
                            4d5e9d27138cfba8f88a566de48f57ed68f04c07
implementation_final_head = 4d5e9d27138cfba8f88a566de48f57ed68f04c07
c2_audit_commit           = 3a5614e8084099469e39a0cf9e279d1c4be26983
c3_commits                = 41ce7eee88614e6e77ed357c7fd4553c8da5d95e,
                            8a1d272d6f84b035e74a79f1eca2141a4f9f4b96
current_audit_tip         = 8a1d272d6f84b035e74a79f1eca2141a4f9f4b96
\`\`\`ini

## C3 status

- C3 evidence is **PARTIAL / SUPERSEDED_BY_C4** (NOT passed).
- C3 manifest raw SHA: 5e15bdcb25588ef73429ec46128a6bacb70615a70d9e9670c1c6461f374faa04 (frozen)
- C3 declared self hash: a4e2c8505eecafe8eeb31ed288ffca1d7513158f5c4c7c5b202e84b842afa91a (defective: used re-serialization)
- C3 byte-level self hash recompute: c8b511479657ae832989bbcfcabac6275fee486e42776d0b1ed96386b38d5d6a
- C3 untracked list sha declared 0f62998f... vs disk 64a883f1... (annotation drift; recorded, not fixed in place)

## C4 deliverables

- manifest: evidence/r5r2/imp09_carrier_r5_r2_c4_manifest.json
  - self_sha256 (byte-level, verifier: evidence/r5r2/verify_c4_manifest.py): 998ed4e68bb62e792e4b6375b855c378c3719676939994e62ec5f58896c281eb
  - raw_file_sha256 (external sidecar): 329e25b47b2d83029ca214ef85fffc8e7156e87acf7377e14aae6ab7d00b24cd
- sidecar: evidence/r5r2/imp09_carrier_r5_r2_c4_manifest.sha256
- capture-time untracked list: evidence/r5r2/imp09_carrier_r5_r2_c4_untracked_list.txt
  - sha256: 143553a85efaec6f5d95948d5cc4bc42c48aa1d3896b1d40ad986e76d1086b1f
  - capture-time untracked_entries: 58
  - tmp_c3_build.py was present in the C3 capture list (historical path; file deleted before C4); the C4 capture list (fresh re-capture) does NOT contain it; capture_time_set != current_live_set is explicit
- verifier: evidence/r5r2/verify_c4_manifest.py (executable, committed)

## Authorization (unchanged)

\`\`\`ini
offline_mock               = true
live_authorized            = false
protected_sample           = NOT_AUTHORIZED
live_4                     = NOT_AUTHORIZED
production_target_dispatch = NOT_IMPLEMENTED
format_gate                = NOT_PASS
\`\`\`ini

Raw walker status=0 remains OFFLINE MOCK only.
