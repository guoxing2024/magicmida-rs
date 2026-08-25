# OVERLAY — CORRECTION-2 is PARTIAL / SUPERSEDED_BY_C3

**Date**: 2026-08-25
**Branch**: codex/imp09-carrier-r5-r2

## Binding

\`\`\`ini
base_head                 = 9cd2e4dffa9c8de3031c78bf8d670688afdd7c78
correction_commits        = 7c0dc8decce897a9a11cce9e1856831dc6e27ca6,
                            f0bd0df706f5636a204744f18e5654bff886620f,
                            4d5e9d27138cfba8f88a566de48f57ed68f04c07
implementation_final_head = 4d5e9d27138cfba8f88a566de48f57ed68f04c07
audit_commit              = 3a5614e8084099469e39a0cf9e279d1c4be26983
\`\`\`ini

## C2 status

- C2 evidence manifest is **PARTIAL / SUPERSEDED_BY_C3** (NOT passed).
- C2 manifest raw SHA-256: a5bef749a82b4314aa04468daa3a534779079dbda67a2db350d55fe348b73b88
  (current disk; the C2 file is FROZEN, unmodified by C3)
- C2 manifest stable self hash (without self field): 0cd40746cbb13ba8cfaf1bcfe426c97fe69d83ba223aa7f766b6a099b941b8ca
- C2 known defects (recorded, not fixed in place): manifest self-entry in listed-vs-disk
  used the self hash instead of the raw file hash; untracked baseline count drifted (51 vs later 52/55).

## C3 deliverables

- manifest: evidence/r5r2/imp09_carrier_r5_r2_c3_manifest.json
  - self_sha256 (without self field): a4e2c8505eecafe8eeb31ed288ffca1d7513158f5c4c7c5b202e84b842afa91a
  - raw_file_sha256 (external sidecar): evidence/r5r2/imp09_carrier_r5_r2_c3_manifest.sha256
- untracked baseline full list: evidence/r5r2/imp09_carrier_r5_r2_c3_untracked_list.txt
- git diff --check raw: evidence/r5r2/git_diff_check_raw.txt (empty, exit 0)

## Authorization (unchanged)

\`\`\`ini
offline_mock               = true
live_authorized            = false
protected_sample           = NOT_AUTHORIZED
live_4                     = NOT_AUTHORIZED
production_target_dispatch = NOT_IMPLEMENTED
format_gate                = NOT_PASS
\`\`\`ini

Raw walker status=0 remains OFFLINE MOCK only; it does not prove production
target-side WalkerExecute success.
