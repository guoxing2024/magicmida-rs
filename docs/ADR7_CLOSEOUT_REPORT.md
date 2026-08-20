# ADR7 CLOSEOUT REPORT — 2026-08-20

> status: CLOSED — B4/B5 formal validation complete, project enters handover phase
> evidence root: D:\MidaVault\lab\evidence
> authority: project-total-audit

## 1. Final formal status (frozen 2026-08-20)

| item | status |
|---|---|
| ADR7 experiment tasks | COMPLETE |
| B4 (runtime binding correction) | **FORMAL PASS** |
| B5 (TLS root-cause isolation) | **FORMAL PASS** |
| B5 TLS isolation evidence | COMPLETE (6/6 target + 6/6 controls) |
| Evidence chain | COMPLETE (root/final/seal verified) |
| Project closeout | this report + index + verifier |
| Next ADR | not yet defined (see §7) |

Frozen packages (no in-place modification; new versions only):

    D:\MidaVault\lab\evidence\adr7b_b4_binding_correction\
    D:\MidaVault\lab\evidence\adr7b_b5\
    D:\MidaVault\scratch\adr7b4_pre_fix_helpers_20260820\
    D:\MidaVault\scratch\adr7b4_noobs1_stale_20260820\

Freeze fingerprints: ADR7_FREEZE_FINGERPRINTS_20260820.json (tree sha256 per path).

## 2. Ledger (ADR7_CLOSEOUT_INDEX.json)

Single index file with: B4 report/seal/manifest/source/helper/runtime hashes,
B5 report/seal/manifest/sign-off/source/helper/runtime hashes, B4→B5 dependency,
shared runtime identity (dll/pdb/offset_map), sample hashes, toolchain,
acceptance date. sha256 = de9a96dff1b35618206f7c91f5bc65933c4b2f58c981049b386888ddccadf0c4

Headline identities:

    B4 report sha256    a330362c58ab11e85fb08ba5a81a692447dc400be677bf1b981600d42c99dd05
    B4 final seal       56b3df5c6ba4fd62759469d4e63db45886b937a12cd52ac88626a7539766f89a   (SEAL_HASH.txt)
    B4 source revision  99f578da4f366d94211c3707e7a19de9740e2e14 (parent 7e65cf6)
    B4 helpers          b1 473e0fc8... / b2 49015f84... / b4 a47995bb... (release profile)
    B5 report sha256    081339b632d94e8aa3d1e7ca9348924134eb9d877f0b8c28be5370cb934d8a35
    B5 final seal       a32c4a513b1adec6863fdd49a91907abd39ec9ed6a601c288a8df0168c81d509   (SEAL_HASH.txt)
    B5 source revision  99f578da4f366d94211c3707e7a19de9740e2e14 (parent b2ae591)
    B5 helpers          b1 58e3eb17... / b2 6a1092a6... / b4 00bfadce... (B5 own profile)
    B5 formal sign-off  ADR7_B5_FORMAL_SIGNOFF.json  sha256 ca6c43ba6319e688571d8fac91b76f153baa74c9045e7901c038dbbf2501f243
    runtime dll/pdb     ae42901e... / b8165cf8... (PDB GUID DDCD43FD-2CFF-4242-85BF-39DC0ADB09E0 age 1)
    offset_map          b0c471587ebbf15e94a3537e77e4ea17e5ea444b43655bf6b6de0c54e0bc95af
    samples (ref-only)  origin_macro 1AF62999... / lunlun_software 8A0118D0...
    toolchain           rustc 1.97.1 MSVC, offline cargo, registry cache D:/DevData/.cargo

## 3. Verification entry

Read-only verifier (does not modify evidence): tools/verify_adr7_closeout.ps1
(committed in the repository at 427c18b..HEAD+closeout).

Checks: B4 seal, B5 seal, report hashes, B5 sign-off hash, root/final/seal
chains, attempt semantic summary, no protected sample copies, helper
provenance. Output: PASS/FAIL + mismatch lists.

## 4. Closed issues (verified resolved)

    B4 runtime offset stale binding            CLOSED (exact runtime binding, offset_map.json)
    B4 actual_int29_address null               CLOSED (6/6 non-null passive + 4/4 active hits)
    B4 c1 false 0xc0000409 count               CLOSED (CONTROL-COUNT-1, real exception counting)
    B4 evidence post-seal mutation             CLOSED (seal 115 files / 0 mismatch, re-verified)
    B5 TLS snapshot missing                    CLOSED (6/6 snapshots persisted in timeline)
    B5 TLS classification missing              CLOSED (6/6 tls_slot_writable)
    B5 control false positive                  CLOSED (6/6 controls clean, no TLS capture)
    B5 seal-chain inconsistency                CLOSED (87/87 entries, root/final/seal verified)

## 5. Residual risk (must be stated alongside FORMAL PASS)

    R1  B4 vs B5 helper build profile differs         (accepted, documented; see sign-off)
    R2  B5 sign-off is an overlay, not inside original seal
        (registered in ADR7_CLOSEOUT_INDEX.json; re-seal would change seal hash and requires decision)
    R3  Evidence depends on local Windows/cdb/rustc toolchain
        (reproduction outside this machine is not automated)
    R4  Samples are reference-only paths, never copied into repo
        (sample availability is required for any re-run)
    R5  FORMAL PASS is scoped to current source revision, runtime artifact,
        helper provenance and sample hashes; it does NOT extend to future builds.
        Any source/helper change invalidates the seal applicability.

## 6. Handover package

    project goal          ADR7 antidebug runtime binding + TLS isolation validation (B4/B5)
    current conclusion    B4 = FORMAL PASS; B5 = FORMAL PASS; TLS evidence COMPLETE
    key commits           7e65cf6, b2ae591, 2e0995f..99f578d (mainline oreans/two-sample-mainline)
    key hashes            §2 ledger
    evidence dirs         D:\MidaVault\lab\evidence\adr7b_b4_binding_correction, adr7b_b5
    verify command        pwsh tools/verify_adr7_closeout.ps1 (read-only)
    closed issues         §4
    residual risks        §5
    forbidden             rerun matrix, modify frozen packages in place, commit samples/binaries
    next stage entry      §7

## 7. Next stage (choose ONE; do not start matrix without it)

Option A — product landing: ADR7 implementation hardening
    - runtime binding fail-closed logic into production path
    - runtime/PDB identity verification
    - offset map generation + versioning
    - TLS/exception telemetry as auditable logs
    - CI provenance checks; forbid stale helpers in release packages

Option B — research: new independent ADR
    - must define: goal, hypothesis, sample set, source revision, runtime
      identity, helper build profile, acceptance criteria, seal rules,
      rollback rules
    - do NOT reuse B4/B5 directories; do NOT append experiments to sealed B5

Until one of these is explicitly authorized, no matrix runs.

## 8. Sign-off

    owner sign-off      PENDING (add name + timestamp)
    reviewer sign-off   PENDING (add name + timestamp)
