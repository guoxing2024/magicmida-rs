# OVERLAY — docs/AUDIT_IMP09_CARRIER_R5_R2_20260825.md is SUPERSEDED

**Date**: 2026-08-25
**Branch**: codex/imp09-carrier-r5-r2
**This overlay is the sibling correction record; the old doc was NOT modified in place.**

## Binding

\`\`\`ini
base_head          = 9cd2e4dffa9c8de3031c78bf8d670688afdd7c78
correction_commits = 7c0dc8decce897a9a11cce9e1856831dc6e27ca6,
                     f0bd0df706f5636a204744f18e5654bff886620f,
                     4d5e9d27138cfba8f88a566de48f57ed68f04c07
final_head         = 4d5e9d27138cfba8f88a566de48f57ed68f04c07
\`\`\`ini

## Status

- The previous document `docs/AUDIT_IMP09_CARRIER_R5_R2_20260825.md`
  (SHA-256 `d7ed84d8c6c69f7bd4be5d2c409e03c16e149bf32d114c9bad1d841be5a694f4`) is **SUPERSEDED** for the purpose of the CURRENT
  final evidence. It is preserved unmodified (historical record).
- The current authoritative evidence manifest is:
  `evidence/r5r2/imp09_carrier_r5_r2_c2_manifest.json`
  (self SHA-256 recorded inside the manifest).
- The old doc's in-text "CORRECTION HEAD: 7c0dc8d..." binding is stale;
  the final correction HEAD is `4d5e9d27138cfba8f88a566de48f57ed68f04c07`.
- The old doc's self-hash line refers to an earlier revision of the doc;
  current disk SHA-256 is `d7ed84d8c6c69f7bd4be5d2c409e03c16e149bf32d114c9bad1d841be5a694f4`. All claims about the OLD doc must
  reference THIS hash.

## Authorization state (unchanged)

\`\`\`ini
offline_mock                     = true
live_authorized                  = false
protected_sample                 = NOT_AUTHORIZED
live_4                           = NOT_AUTHORIZED
production_target_dispatch       = NOT_IMPLEMENTED
format_gate                      = NOT_PASS
\`\`\`ini

Raw walker `status=0` in `evidence/r5r2/mida_antidebug_walker.evidence.json`
is the OFFLINE MOCK bridge's status and does NOT prove production
target-side WalkerExecute success.
