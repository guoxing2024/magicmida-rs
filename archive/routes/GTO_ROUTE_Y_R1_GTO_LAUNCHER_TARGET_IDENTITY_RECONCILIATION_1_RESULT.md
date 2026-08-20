# RouteY_R1_GTO_LAUNCHER_TARGET_IDENTITY_RECONCILIATION_1 — Result

**Status:** `RouteY_R1_GTO_LAUNCHER_TARGET_IDENTITY_RECONCILIATION_1_ReviewRequested`
**Mode:** EVIDENCE / CHAIN-OF-CUSTODY / READ-ONLY ONLY
**Date:** 2026-08-14T11:46:23.670Z

## Path-SHA mismatch PROVEN

| | legacy path file | vault artifact |
|---|---|---|
| path | D:\Tools\RE\dumps\gto\启动器.exe | D:\MidaVault\vault\sha256\4d\4d5770af...\artifact.exe |
| SHA-256 | 8EF2A95E... | 4D5770AF... |
| size | 23,501,824 | 8,583,680 |
| protector | Themida (.fptable) | .KI3 AHK packer |
| AHK strings | absent | present |
| vault registered | NO | YES (case=gto_launcher) |

The two files are different binaries. The project-documented path does NOT hold the project target.

## Canonical provenance

4d5770af = `runtime_triage/original_sample.exe` (2026-06-29) → registered in corpus_object_manifest.json
(2026-07-22, case=gto_launcher, protected_or_control_input) → vault artifact.exe (2026-08-08).
All 11 GTO work orders used 4d5770af. None used 8ef2a95e as input.

## Locator policy (draft)

identity = immutable SHA+size+provenance; locator = mutable audited path. Options A (vault canonical),
B (controlled restore), C (pause) drafted but NOT executed — requires separate audit authorization.

## Float errata

0xEEFFEEFF = finite IEEE-754 float32 ≈ -3.96e28, **mantissa 0x7FEEFF** (not 0x6FFEEFF). Errata index created;
no historical root modified.

## Deliverables

14 files in `D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_target_identity_reconciliation_1_20260814T124500Z` (9 payloads + manifest/sidecar/selfcheck/freeze_before/freeze_after).
Manifest SHA `fe8bcfee21930fdc213fabf6a1f0631950e2f09f718b5804a3994d4f110a8403`, selfcheck PASS, strict order verified.

## Boundaries

No sample started, no source modified, no artifact moved/replaced/copied/deleted, no historical evidence
root modified, no commit/push/git add, no dynamic observation.
