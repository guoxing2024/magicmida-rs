# P9-Prep-C: Isolated Replay Ledger

> Batch: P9-Prep Final Acceptance Harness Closure (offline; no live authorization)
> Start HEAD: `1caae82d3c51575244c967d120d271ff7b9ad25e`
> Offline only. No real sample launched. No P9 live executed.

## Scope

Production model + atomic recording semantics + independent verifier for the
isolated replay attempt ledger
(`crates/acceptance/src/isolated_replay_ledger.rs`,
`mida.oreans-isolated-replay-ledger/v1`).

## Ledger contract

A final valid ledger for one case must satisfy:

- **Exactly 10 attempts** (not "at least 10"); `attempt_index` strictly `1..=10`
  in order.
- Every attempt binds: candidate digest, case runner-config digest, CLI SHA,
  verifier path identity + SHA, tool revision, execution root / run id, attempt
  output dir, and the sealed hashes of the bundle / behavior / survival /
  structural artifacts.
- Every attempt: `exit_code == Some(0)`, `signal == None`,
  `observable_verdict == Pass`, `retry_picked == false`, non-empty timestamp,
  `state == Completed`, valid completion marker.
- All ten `runner_config_digest` identical (and equal to the ledger's).
- Sealed self-hash `artifact_self_sha256` verified.

## States and stop rules

The ledger distinguishes per-attempt states: `planned`, `started`,
`process_created`, `completed`, `failed`, `batch_stopped`.

- Attempts are appended/sealed atomically and in order.
- A failed attempt is retained forever — never deleted, overwritten, or renamed
  to a success.
- Any failing attempt (launch/preflight/attestation failure, timeout, non-zero
  exit, signal, invalid bundle, structural/behavior/survival failure,
  identity/digest drift, partial artifact, output collision, environment drift)
  stops the whole case/batch.
- No backfill replacement of a failed attempt; no selecting ten successes from
  multiple runs; P7-R2 smoke is never auto-counted into a new 10/10; no stitching
  across revisions / candidates / runner configs / execution roots.
- Only ten consecutive, same-config, same-identity, all-valid attempts produce a
  10/10 Pass.

## Attack tests (27 total)

Covers: valid 10/10; 9/10; 11/10; index from 0; missing number; duplicate number;
out-of-order; runner-config digest drift; candidate digest drift; tool revision
drift; CLI drift; verifier drift; retry_picked=true; signal non-null; exit
failure; behavior failure; malformed bundle hash; partial artifact binding;
cross-case attempt; appended success after a retained failed attempt; selecting
10 successes from 11; cross-execution-root stitching; output collision; unknown
schema; unknown field; honest-recompute identity swap; stale self-hash mismatch.

Result: `cargo test -p mida-acceptance --lib isolated_replay_ledger --offline`
→ **27 passed, 0 failed**; full acceptance lib suite 156 passed.
