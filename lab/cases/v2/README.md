# Case Manifest v2

These manifests identify corpus artifacts by SHA-256 without embedding a
workspace or Vault path. A consumer resolves each digest through a configured
content-addressed store and verifies both `sha256` and `size_bytes` before use.

The contract contains no acceptance, perfection, or recovery claim.
`capability_cell` is a routing coordinate, not a result. An `oracle` is only a
named comparison source and cannot grant acceptance status to an artifact.
Origin FE92 is therefore recorded only as a `legacy_oracle_candidate`.

Dynamic execution remains outside manifest authority. A manifest with
`explicit_authorization_required` fixes the artifact digest, timeout, process
tree accounting, and network isolation requirements, but a separate current
authorization is still required before execution. A `forbidden` policy carries
no executable digest or timeout.

Run the fail-closed verifier from the repository root:

```powershell
python -B lab\cases\verify_manifests.py --objects-root D:\MidaVault\objects\sha256
python -B -m unittest lab\cases\test_verify_manifests.py -v
```

The verifier requires the Python `jsonschema` package. A missing validator,
schema error, object mismatch, dangling reference, legacy path, cross-field
semantic conflict, or self-certifying claim produces a nonzero exit code.

### Oreans holdout slot (R3-path-B)

`capability_cell.corpus_role` may be `holdout` for a **third** Oreans sample that
is not Origin/Lunlun. Registration procedure: [HOLDOUT_SLOT.md](HOLDOUT_SLOT.md).
The slot is empty until a vault object and real manifest exist. Engineering
tools report `holdout_status=empty` and still refuse `--claim-r3`.
