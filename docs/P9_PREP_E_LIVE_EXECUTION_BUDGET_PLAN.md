# P9-Prep-E: Live Execution and Budget Plan

> Batch: P9-Prep Final Acceptance Harness Closure (offline; no live authorization)
> Start HEAD: `1caae82d3c51575244c967d120d271ff7b9ad25e`
> This document is a **plan and budget application only**. No process is executed
> by this work order. The budget is applied for; it is NOT self-approved.
>
> **Live authorization is required before any of the process budgets below are
> spent.** This work order stops here and awaits an independent P9 live
> authorization issued against the final HEAD, binary SHAs, runner config digests,
> tool identities, and the exact process budget below.

## 1. Final candidate HEAD

- Branch: `oreans/two-sample-mainline`
- Final candidate HEAD for the live run: **`d0b98256c3efefdd51e50138d1baaeadd681cd30`**
  (P9-Prep-D two-bundle envelope consumer). This is the HEAD after the full
  P9-Prep A–D closure.
- Working tree must be clean before the live run.

## 2. Baseline participation (SEMANTICS_B: protected vs candidate)

P9 acceptance semantics are **protected-sample behavior vs candidate unpacked
output** (SEMANTICS_B, per P9-RESET-A). The word "baseline" in the historical
P7-R2 context refers to a **toolchain-revision worktree** (`858f66e`) used to
verify a fix, NOT a P9 acceptance input. The P7-R2 baseline report
(`mida.oreans-two-sample-bundle-gate/v1`) is **not a live input** to the P9
gate. It is used only as a **regression cross-check** of the offline taxonomy
counts (337/1504) and of the bundle-gate report shape. It does **not**
contribute any live process, candidate, or replay evidence, and its smoke
attempts are **never** auto-counted into the new 10/10 (P9-Prep-C #6).

The 46-process / 22-slot budget below covers **protected reference behavior +
candidate final live unpack + candidate isolated replay** only. It contains
**no baseline-revision process**: a historical toolchain baseline is not
launched, not un-packed, and not compared as a live acceptance side.

## 3. Protected / reference behavior runs (per case)

For each of `origin_macro` and `lunlun_software`, **1** protected reference
behavior run under the case-specific canonical stimulus plan, with network deny
and bounded observation window. This produces the reference side of the
behavior-oracle comparison (`protected` observables).

## 4. Candidate behavior runs (per case)

For each case, **1** candidate behavior run under the **same** canonical stimulus
plan, producing the candidate-side observables compared by the behavior oracle.

## 5. Isolated replay count (per case)

**Exactly 10** isolated replay attempts per case (P9-Prep-C ledger), `attempt_index`
strictly 1..=10. Each attempt is an independent process run that independently
reproduces the unpack and collects behavior/survival/structural evidence. No
retry selection; a failed attempt is retained and stops the case/batch.

## 6. Candidate evidence/dump vs replay-attempt collection

Per the P9-Prep-C ledger model, **each replay attempt is itself an independent
unpack run** that produces its own candidate, bundle, and behavior/survival/
structural artifacts (`bundle_sha256`, `behavior_artifact_sha256`,
`survival_artifact_sha256`, `structural_artifact_sha256`). Therefore the
10 replay attempts **also serve as** the replay evidence; no separate dump is
needed for the replay ledger.

However, the **final candidate** used for the fixed-case gate and for the
candidate-identity binding is produced by a **separate live unpack** (this cannot
be proven to equal any single replay attempt's candidate because the budget
application cannot, offline, prove that one replay attempt's candidate is
byte-identical to the final one). Per the "do not optimistically merge" rule,
the final candidate unpack is budgeted **separately** from the 10 replay attempts.

## 7. Survival observation reuse

The survival observation (process creation, PID, start/end, observation window,
exit code, timeout/forced-termination, survival verdict) is collected **within the
same run** that produces each evidence artifact — the unpack run (protected
process) and the behavior candidate run both already create and observe a process.
Survival observation therefore **reuses** those runs; no additional process is
budgeted for survival. This is provable because survival is defined as "the
process was created and observed within the window", which the unpack/behavior
runs already record.

## 8. Structural evidence reuse

Structural evidence is derived from the Evidence Bundle v2 validation +
per-domain verdicts. Each unpack/replay run already produces a sealed bundle
(assembled atomically), so structural evidence **reuses** that run's bundle. No
additional process is budgeted for structural evidence.

## 9. Total process creation budget

Per case:
- Final live unpack (protected process, debugger attach → candidate + bundle):
  **1**
- Protected reference behavior run (protected process): **1**
- Candidate behavior run (candidate process): **1**
- Isolated replay × 10 (each: protected unpack process **and** candidate behavior
  process): **20** (10 protected + 10 candidate)

Per case subtotal: **23** sample processes.
Two cases: **46** sample processes.

## 10. Total live unpack slot budget

"Live unpack slot" = a run that launches a protected process and attaches the
debugger to unpack it:
- Per case: final live unpack **1** + replay unpack × 10 = **11**
- Two cases: **22** unpack slots.

## 11. Protected vs candidate process count

- Protected processes (all cases): final unpack 1×2 + reference behavior 1×2 +
  replay protected 10×2 = **24**
- Candidate processes (all cases): candidate behavior 1×2 + replay candidate
  behavior 10×2 = **22**
- Total sample processes = **46**.

## 12. Per-case count

Each of `origin_macro` and `lunlun_software`:
- 1 final live unpack (protected)
- 1 protected reference behavior
- 1 candidate behavior
- 10 replay (10 protected unpack + 10 candidate behavior)
- = 23 processes, 11 unpack slots.

## 13. No-retry rule

If any replay attempt fails (launch/preflight/attestation failure, timeout,
non-zero exit, signal, invalid bundle, structural/behavior/survival failure,
identity/digest drift, partial artifact, output collision, environment drift),
the whole case/batch stops immediately. The failed attempt is retained forever;
it is never deleted, overwritten, renamed to success, or backfilled.

## 14. Batch stop rule

The batch stops on the first failing attempt or on any live precondition failure.
No attempt is re-run after a stop; no 10 successes are selected from more runs;
P7-R2 smoke is never counted; no stitching across revisions/candidates/runner
configs/execution roots.

## 15. Per-phase timeout

- Final live unpack: 120 s (per case execution policy `timeout_seconds: 120`).
- Protected reference behavior run: 120 s.
- Candidate behavior run: 120 s.
- Each replay attempt: 120 s.
- Batch total budget: 46 × 120 s ≈ 92 min worst case (parallelizable per case but
  budgeted conservatively).

## 16. Execution root / run id / attempt directory naming

- Execution root: `D:/MidaVault/scratch/p9_live_<run_short>_<yyyyMMdd_HHmmss>/`
- Run id: `p9_live_<case_id>_<8-hex-short>` per case.
- Attempt output dir: `root/<case_id>/replay/attempt-<1..10>/`
- Final unpack output dir: `root/<case_id>/final/`

## 17. Output collision / stale evidence check

Before each run and before the final gate:
- Verify every attempt output dir is unique (no `OutputCollision`).
- Verify no stale `candidate.*.bundle.json` / sidecar from a prior revision remains
  in the execution root (delete-or-refuse per stale-evidence policy).
- Verify the sealed `artifact_self_sha256` on every ledger/evidence document.

## 18. ScyllaHide three-file deployment + SHA-256

Before any live run, deploy and SHA-256-verify (all lowercase 64-hex):
- `ScyllaHide/InjectorCLIx64.exe`
- `ScyllaHide/HookLibraryx64.dll`
- `ScyllaHide/scylla_hide.ini`
The SHA-256 of each must be recorded in the run's identity table and re-verified
immediately before launch. (Exact SHAs are computed at live time, not fabricated
here.)

## 19. Rebuild candidate CLI/verifier + recompute SHA-256

The candidate `mida-acceptance.exe` (verifier) and `mida-cli.exe` (runner) must be
rebuilt from the final HEAD and their SHA-256 recomputed. A stale binary from a
prior revision is rejected.

## 20. No reuse of P7-R2 envelope/preflight

Because the HEAD has changed since P7-R2, the P7-R2 envelope/preflight is **not**
reused. A fresh runner-config envelope and preflight must be produced for the
final HEAD.

## 21. New case-bound runner config digest

Each case gets a **new** case-bound runner-config digest generated for the final
HEAD; all ten replay attempts of a case must carry the identical digest.

## 22. Complete identity table

| Entity | Identity |
|---|---|
| Candidate protected input (origin) | locked `1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7` (5,232,656 B) |
| Candidate protected input (lunlun) | locked `8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07` (4,976,144 B) |
| Final candidate HEAD | `d0b98256c3efefdd51e50138d1baaeadd681cd30` |
| mida-cli.exe | recompute at live time |
| mida-acceptance.exe | recompute at live time |
| ScyllaHide 3 files | recompute at live time |
| runner config digest (per case) | generate at live time |
| tool revision | `oreans/two-sample-mainline@<final>` |

## 23. Pre-live environment checks

- Disk space: verify ≥ 10 GB free in the execution root.
- Directory permissions: verify read/write on `D:/MidaVault/scratch/`.
- Process residue: verify no prior protected/candidate process remains.
- `git status --short` must be empty and HEAD must equal the pinned final HEAD.

## 24. External conditions

- UI / network / system time: network is **deny_all** for every run. Any UI
  dependency must be either fixed (headless/ScyllaHide) or recorded. System time
  must be recorded (used in `emitted_at` / timestamps); no NTP drift is assumed.

## 25. Final gate input file list and generation order

1. Final candidate PE (from final live unpack).
2. Five sidecars (OEP/IAT/TLS/reloc/section) from final unpack + replay.
3. Transform manifest.
4. PE evidence.
5. Evidence Bundle v2 (atomic assembler, one per case final + per replay attempt).
6. Behavior oracle contract evidence (P9-Prep-A) for protected + candidate.
7. Survival evidence (P9-Prep-B) per run.
8. Structural evidence (P9-Prep-B) per bundle.
9. Isolated replay ledger (P9-Prep-C), 10 attempts per case.
10. All fed to the v8 two-sample gate + two-bundle envelope consumer.

## Budget classification summary

| Class | Count |
|---|---|
| unpack/debugger process slots | 22 (11 per case) |
| protected reference behavior processes | 2 (1 per case) |
| candidate behavior processes | 22 (11 per case: 1 final + 10 replay) |
| isolated replay processes | 20 (10 per case) |
| auxiliary verifier/CLI subprocesses | offline commands, no sample process |
| pure offline commands (verifier, classifier) | not counted as sample processes |

Total sample processes: **46**. This is the **applied-for** live budget. It is
conservative: final candidate is separate from replay attempts, and behavior
candidate runs are separate per replay because offline we cannot prove they merge.
If a future reconciliation can prove a merge, the budget may be reduced, but this
application does not claim that.

**This is a budget application only. It is NOT approved. A separate P9 live
authorization is required before any process in this budget is created.**
