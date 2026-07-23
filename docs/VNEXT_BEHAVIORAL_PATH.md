# VNEXT Behavioral Acceptance Path

Status: **B-A0 DONE** (2026-07-23) — contract + scope + evidence schema only.
No code path may return `Accepted` until a later scheduled behavioral gate
writes `validation_summary` task **VNEXT-BEH** (name reserved; not open).

Prerequisites: R0B static kernel + R1 pure PE + R2 runtime + **R3/R4 structural
gates closed**. Pure default flip is **orthogonal** and still **No**.

Related: [ACCEPTANCE_CONTRACT.md](ACCEPTANCE_CONTRACT.md) (R0B still binding),
[VNEXT_ARCHITECTURE.md](VNEXT_ARCHITECTURE.md).

---

## What behavioral acceptance is

Independent evidence that a **candidate PE** (unpacked dump that already passes
R0B structural gates) is **behaviorally equivalent** to a declared reference
under a controlled, offline-friendly probe — not that a packer plugin “thinks”
the dump is good.

| Actor | Role |
|-------|------|
| `mida-acceptance` | Owns verdict composition; may load **pre-recorded** behavioral evidence; still **no** packers / debugger / Win32 in the kernel |
| Probe harness (future, outside kernel) | Runs candidate (and optional reference) under policy; writes evidence JSON to vault |
| Production unpacker / plugins | Produce candidate bytes only; never self-judge `Accepted` |

**R0B rule remains:** static evaluation alone must never emit `Accepted`.

---

## Explicit non-claims (B-A0)

- Writing this document does **not** enable `Verdict::Accepted`.
- StructuralPass on Origin/Lunlun/GTO is **not** behavioral pass.
- Live unpack green is **not** behavioral evidence.
- Oracle PE byte-match is **not** behavioral equivalence.
- Network, interactive UI, and full product E2E are **out of scope** for the
  first behavioral MVP.

---

## Scope (MVP → later)

### In scope for first implementable slice (B-A1+)

1. **Evidence document** on disk (schema below), produced by a harness the
   acceptance crate does **not** import.
2. **Static composition rule** in acceptance:  
   `structural == StructuralPassBehaviorPending` **and** evidence verdict pass  
   → allow `Accepted` **only** when a feature flag / CLI mode is explicitly on
   and contract docs say so (default off until gate).
3. **Deterministic, no-network probes** against the candidate PE file:
   - Load as image under a controlled host (job object / sandbox policy TBD in B-A1).
   - Bounded runtime wall-clock and CPU.
   - Optional: process exit code, presence of a marker file/stdout line written
     by a **test-only** reference binary path (synthetic first).
4. **Synthetic / lab-owned** PE pairs before any vault malware-shaped sample.

### Explicitly deferred

| Item | When |
|------|------|
| API trace / ETW / debugger API log scoring | After synthetic exit+I/O MVP |
| Origin/Lunlun/holdout live behavioral gate | After harness stable on synthetic |
| GTO behavioral | Separate; experimental dump profile only |
| Default pure rebuild flip | Phase2 decision; not behavioral |
| Full loader equivalence vs original protected input | Research; not MVP |
| Returning `Accepted` from `check-static` without evidence file | **Forbidden forever** |

### Hard policy

- **No network** during probe (block or fail closed).
- Evidence must bind to **candidate sha256 + size** (same identity model as R0B).
- Probe must not mutate vault object store payloads; write only under
  `lab/evidence/...` or designated scratch.
- Acceptance crate dependencies: still no `mida-core`, `mida-pe`, packers, cli.

---

## Verdict composition (future; not implemented in B-A0)

```text
static_verdict = check_static(candidate)
if static_verdict == Rejected:
    final = Rejected
elif no behavioral evidence supplied:
    final = StructuralPassBehaviorPending   # R0B behavior
elif evidence.identity mismatches candidate:
    final = Rejected                        # fail-closed
elif evidence.verdict == Fail:
    final = Rejected                        # or keep Pending? → Fail → Rejected
elif evidence.verdict == Pass and structural pass:
    final = Accepted                        # only when behavioral mode enabled
else:
    final = StructuralPassBehaviorPending
```

**B-A0 decision:** until implementation lands, `check-static` and library
`evaluate_*` paths stay R0B-only (`Accepted` = contract violation).

CLI sketch (not shipped):

```text
mida-acceptance check-static <candidate> --report r.json
mida-acceptance check-with-behavior <candidate> --behavior-evidence e.json [--report r.json]
```

Exit codes (planned):

| Code | Meaning |
|------|---------|
| `0` | `Accepted` **or** `StructuralPassBehaviorPending` (document which mode) |
| `2` | `Rejected` |
| `1` | I/O / config / contract violation |

Prefer **distinct** exit for Pending vs Accepted in a later CLI revision if
scripts need it; do not break R0B `0` = Pending without a version bump note.

---

## Evidence schema (MVP draft)

File: JSON, UTF-8, **deterministic** field order preferred; no hostnames,
absolute paths, or wall-clock timestamps inside the signed/compared body.

```json
{
  "schema_version": "mida.behavior-evidence/v0",
  "candidate": {
    "sha256": "lowercase hex",
    "size_bytes": 0,
    "role": "candidate"
  },
  "reference": {
    "kind": "none | synthetic_pair | oracle_observation",
    "sha256": null,
    "notes": "optional; non-authoritative"
  },
  "probe": {
    "id": "exit_code_v0 | marker_file_v0 | ...",
    "policy": {
      "network": "deny",
      "max_wall_ms": 5000,
      "max_output_bytes": 65536
    },
    "result": {
      "status": "pass | fail | error | timeout",
      "exit_code": null,
      "markers_found": [],
      "error_class": null
    }
  },
  "verdict": "Pass | Fail | Inconclusive",
  "residual_risks": [],
  "producer": {
    "name": "harness id",
    "version": "semver or git describe"
  }
}
```

### Semantics

| `evidence.verdict` | Meaning |
|--------------------|---------|
| `Pass` | Probe succeeded under policy; eligible to compose to `Accepted` with structural pass |
| `Fail` | Probe ran and observed disallowed / mismatched behavior |
| `Inconclusive` | Timeout, harness error, sandbox denial — **must not** upgrade to `Accepted` |

### Binding

Acceptance must recompute candidate sha256/size and reject evidence that does
not match. Tampered or stale evidence → fail closed.

---

## Milestones

| ID | Work | Status |
|----|------|--------|
| **B-A0** | This contract: scope, non-claims, evidence schema, composition rules | **done** |
| B-A1 | Synthetic PE fixture + offline probe harness (no vault malware); emit evidence JSON | pending |
| B-A2 | `mida-acceptance` load/validate evidence; composition path behind explicit CLI; unit tests; still default Pending | pending |
| B-A3 | Wire lab smoke: structural dump → probe → evidence (Origin **optional**, synthetic required first) | pending |
| B-B | Scheduled behavioral gate + `validation_summary` **VNEXT-BEH** (only when deliberately opened) | not open |
| B-C | Multi-probe scoring / API-trace (post-MVP) | deferred |

Anything short of a scheduled **B-B** is engineering, not “behavioral closed”.

---

## First probe design (B-A1 target)

**`exit_code_v0` (synthetic only):**

1. Build or store a tiny console PE that exits with code `0` and writes one
   marker line to a temp file under scratch.
2. Run under job object: no child network, wall clock ≤ 5s.
3. Evidence `Pass` iff exit 0 and marker present.
4. Negative tests: wrong exit, missing marker, timeout → `Fail` / `Inconclusive`.

Do **not** start with protected samples. Protected→unpacked behavioral comes
only after synthetic composition is green.

---

## Residual risks (carry-forward)

- Windows loader success ≠ product behavior equivalence.
- ASLR / timing flakiness → prefer markers and exit codes over wall timing.
- Probe host privilege and AV interference on lab machines.
- Shared PE parser residual remains R0B topic; behavioral harness may use
  production PE loaders **outside** the acceptance crate.
- Operators may pressure for early `Accepted` on StructuralPass — refuse without evidence.

---

## Validate (B-A0 only)

```text
# Docs only — no behavioral gate, no Accepted:
# - docs/VNEXT_BEHAVIORAL_PATH.md exists
# - ACCEPTANCE_CONTRACT.md still forbids Accepted in R0B
# - validation_summary task remains VNEXT-R4 (not VNEXT-BEH)
```

## Command hygiene

- Do not add `--claim-accepted` without evidence binding.
- Do not teach plugins to emit acceptance verdicts.
- Vault PE samples stay vault-only; synthetic fixtures may live in-repo under
  `crates/acceptance/tests/fixtures/` or lab synthetic paths.
