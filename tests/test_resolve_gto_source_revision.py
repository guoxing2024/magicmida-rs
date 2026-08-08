"""Synthetic tests for the manifest-pinned GTO sample revision resolver.

All tests use temp directories and synthetic bytes. No real mutable sample is
read, no protected sample is launched, and no vault content is touched.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
CORE_PY = REPO_ROOT / "tools" / "_resolve_gto_source_revision.py"
WRAPPER_PS1 = REPO_ROOT / "tools" / "resolve_gto_source_revision.ps1"
AUTHORIZED_MANIFEST = REPO_ROOT / "lab" / "cases" / "v2" / "gto_launcher.json"

sys.path.insert(0, str(REPO_ROOT / "tools"))
import _resolve_gto_source_revision as resolver  # noqa: E402

# constants mirrored from the core
EXIT_OK = resolver.EXIT_OK
EXIT_SOURCE_CHANGED = resolver.EXIT_SOURCE_CHANGED
EXIT_SAMPLE_MISMATCH = resolver.EXIT_SAMPLE_MISMATCH
EXIT_UNAVAILABLE = resolver.EXIT_UNAVAILABLE
EXIT_VAULT_CORRUPT = resolver.EXIT_VAULT_CORRUPT
EXIT_MANIFEST_INVALID = resolver.EXIT_MANIFEST_INVALID
EXIT_SOURCE_INVALID = resolver.EXIT_SOURCE_INVALID
EXIT_RECORD_WRITE_FAILED = resolver.EXIT_RECORD_WRITE_FAILED


def sha256b(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_manifest(
    *,
    payload_sha: str,
    size: int,
    schema_version: str = "mida.case-manifest/v2",
    case_id: str = "gto_launcher",
    revision: int = 1,
    primary_sha: str | None = None,
    fixed_sha: str | None = None,
    mode: str = "explicit_authorization_required",
    duplicate_key: bool = False,
    n_protected: int = 1,
    size_val: object | None = None,
    include_exec_policy: bool = True,
) -> dict:
    primary_sha = primary_sha if primary_sha is not None else payload_sha
    fixed_sha = fixed_sha if fixed_sha is not None else payload_sha
    artifacts = []
    for i in range(n_protected):
        artifacts.append(
            {
                "sha256": payload_sha,
                "size_bytes": size_val if size_val is not None else size,
                "role": "protected_input",
            }
        )
    manifest = {
        "$schema": "./case-manifest.schema.json",
        "schema_version": schema_version,
        "manifest_revision": revision,
        "case_id": case_id,
        "display_name": "fixture",
        "primary_artifact_sha256": primary_sha,
        "artifacts": artifacts,
        "capability_cell": {
            "platform": "windows",
            "binary_format": "pe",
            "architecture": "x86_64",
            "execution_model": "native",
            "protection_family": "ahk_gto_candidate",
            "engine_route": "mida_plugin_ahk_gto",
            "corpus_role": "research",
        },
        "static_fingerprint": {
            "artifact_sha256": primary_sha,
            "evidence_basis": "retained_static_report",
            "pe_kind": "PE32+",
            "coff_machine": "0x8664",
            "image_base": "0x140000000",
            "entry_rva": "0x1000",
            "entry_section": ".text",
            "section_count": 1,
            "import_descriptor_count": 0,
            "has_tls": False,
            "has_relocations": False,
            "observed_markers": [],
        },
        "execution_policy": {
            "dynamic": {
                "mode": mode,
                "fixed_sha256": fixed_sha,
                "timeout_seconds": 120,
                "process_tree_accounting_required": True,
            },
            "network": {
                "mode": "deny_all",
                "network_actions_allowed": False,
                "isolation_evidence_required": True,
            },
        } if include_exec_policy else {},
        "oracle": {
            "oracle_id": "fixture",
            "kind": "analysis_reference",
            "artifact_sha256": payload_sha,
            "authority": "historical_tool_output",
            "use": "analysis_comparison_only",
        },
    }
    if duplicate_key:
        # Simulate a duplicate key by emitting raw JSON text with a repeated key.
        pass
    return manifest


class ResolverTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.vault_root = root / "vault"
        self.evidence = root / "evidence"
        self.observed = root / "observed"
        self.manifest_dir = root / "manifests"
        self.manifest_dir.mkdir()
        self.vault_root.mkdir()
        self.evidence.mkdir()
        self.observed.mkdir()
        self.real_payload = b"MZ" + b"\x90" * 64  # synthetic, never executed
        self.payload_sha = sha256b(self.real_payload)
        self.payload_size = len(self.real_payload)

    def tearDown(self):
        # Restore any injected hooks.
        resolver.HASH_FILE_HOOK = None
        resolver.SIZE_HOOK = None
        self.temp.cleanup()

    # ---- helpers ------------------------------------------------------
    def write_manifest(self, manifest: dict, name: str = "case.json") -> Path:
        p = self.manifest_dir / name
        p.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return p

    def seed_vault(self, data: bytes) -> Path:
        # Place `data` at the path derived from the MANIFEST-EXPECTED digest
        # (self.payload_sha), so tests can put wrong bytes at the *right* path.
        vp = resolver.vault_object_path(self.vault_root, self.payload_sha)
        vp.parent.mkdir(parents=True, exist_ok=True)
        vp.write_bytes(data)
        return vp

    def write_source(self, data: bytes) -> Path:
        p = self.manifest_dir / "mutable_sample.bin"
        p.write_bytes(data)
        return p

    def run_resolve(
        self,
        manifest: dict,
        *,
        source: Path | None = None,
        force_acquire: bool = False,
        retain_unmatched: bool = False,
        observed_dir: Path | None = None,
    ) -> tuple[int, dict | None]:
        mpath = self.write_manifest(manifest)
        try:
            result = resolver.resolve(
                manifest_path=mpath,
                case_id=manifest.get("case_id", "gto_launcher"),
                vault_root=self.vault_root,
                evidence_dir=self.evidence,
                source_path=source,
                force_acquire=force_acquire,
                retain_unmatched=retain_unmatched,
                observed_revisions_dir=observed_dir or self.observed,
            )
            return resolver.EXIT_OK, result
        except resolver.ResolverError as exc:
            return exc.exit_code, None

    def read_record(self) -> dict | None:
        rp = self.evidence / "resolved_source.json"
        if not rp.exists():
            return None
        return json.loads(rp.read_text(encoding="utf-8"))


# ===========================================================================
# Section A: authorized vault-first resolution
# ===========================================================================

class AuthorizedVaultTests(ResolverTestCase):
    def test_01_correct_vault_object_resolves(self):
        vp = self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, result = self.run_resolve(manifest)
        self.assertEqual(exit_code, EXIT_OK)
        self.assertIsNotNone(result)
        self.assertTrue(result["revision_match"])
        self.assertEqual(result["resolution_status"], "ResolvedAuthorizedRevision")
        self.assertEqual(result["resolution_mode"], "authorized_vault")
        self.assertTrue(result["vault_object_verified"])
        self.assertEqual(result["resolved_vault_path"], str(vp))

    def test_02_vault_present_ignores_missing_source(self):
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        # SourcePath points to a nonexistent file; must still succeed because
        # the authorized vault object is authoritative and the locator is unused.
        missing = self.manifest_dir / "does_not_exist.bin"
        exit_code, result = self.run_resolve(manifest, source=missing)
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(result["source_stable_during_snapshot"], None)
        self.assertEqual(result["mutable_locator"], str(missing))

    def test_03_vault_present_ignores_different_source(self):
        self.seed_vault(self.real_payload)
        other = b"DIFFERENT-" + b"\x00" * 40
        source = self.write_source(other)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, result = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_OK)
        # The locator must NOT have been read (observed stays None, mode vault).
        self.assertEqual(result["resolution_mode"], "authorized_vault")
        self.assertEqual(result["observed_sha256"], self.payload_sha)

    def test_04_vault_path_exists_but_bytes_wrong(self):
        self.seed_vault(b"\x90" * self.payload_size)  # wrong bytes, right size not yet
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, _ = self.run_resolve(manifest)
        self.assertEqual(exit_code, EXIT_VAULT_CORRUPT)

    def test_05_vault_size_correct_but_hash_wrong(self):
        # Right size, wrong content -> wrong hash. Must be rejected.
        wrong = b"\x00" * self.payload_size
        self.seed_vault(wrong)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, _ = self.run_resolve(manifest)
        self.assertEqual(exit_code, EXIT_VAULT_CORRUPT)

    def test_20_idempotent_on_existing_correct_vault(self):
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        ec1, _ = self.run_resolve(manifest)
        ec2, _ = self.run_resolve(manifest)
        self.assertEqual(ec1, EXIT_OK)
        self.assertEqual(ec2, EXIT_OK)

    def test_21_existing_wrong_vault_cannot_be_overwritten(self):
        vp = self.seed_vault(b"\x00" * self.payload_size)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, _ = self.run_resolve(
            manifest, source=self.write_source(self.real_payload)
        )
        self.assertEqual(exit_code, EXIT_VAULT_CORRUPT)
        # Original wrong bytes remain (no overwrite happened).
        self.assertEqual(vp.read_bytes(), b"\x00" * self.payload_size)

    def test_30_vault_first_does_not_consume_live_round(self):
        # Vault-first success must not read locator: source absent, still OK.
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, result = self.run_resolve(manifest)
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(result["source_stable_during_snapshot"], None)
        self.assertTrue(result["vault_object_verified"])


# ===========================================================================
# Section B: mutable acquisition
# ===========================================================================

class MutableAcquisitionTests(ResolverTestCase):
    def test_06_vault_missing_stable_source_matches_imports(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        exit_code, result = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(result["resolution_mode"], "mutable_snapshot")
        self.assertTrue(result["source_stable_during_snapshot"])
        self.assertTrue(result["revision_match"])
        # Vault object now exists and verifies.
        vp = resolver.vault_object_path(self.vault_root, self.payload_sha)
        self.assertTrue(vp.exists())
        self.assertEqual(resolver.sha256_file(vp), self.payload_sha)

    def test_07_H1_H2_H3_divergence_is_source_changed(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        # Inject a hook that simulates the source changing between hash passes.
        calls = {"n": 0}

        def flaky_hash(path):
            calls["n"] += 1
            if calls["n"] == 3:  # H3 differs
                return sha256b(b"CHANGED-" + path.read_bytes())
            return resolver.sha256_file(path)

        resolver.HASH_FILE_HOOK = flaky_hash
        exit_code, _ = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_SOURCE_CHANGED)

    def test_08_stable_source_hash_differs_is_mismatch(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(b"WRONG-HASH-" + b"\x00" * 40)
        exit_code, _ = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_SAMPLE_MISMATCH)

    def test_09_stable_source_size_differs_is_mismatch(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload + b"\x01")  # +1 byte
        exit_code, _ = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_SAMPLE_MISMATCH)

    def test_10_source_missing_and_no_vault_is_unavailable(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        missing = self.manifest_dir / "nope.bin"
        exit_code, _ = self.run_resolve(manifest, source=missing)
        self.assertEqual(exit_code, EXIT_UNAVAILABLE)

    def test_10b_no_source_and_no_vault_is_unavailable(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, _ = self.run_resolve(manifest, source=None)
        self.assertEqual(exit_code, EXIT_UNAVAILABLE)

    def test_11_source_is_directory_is_source_invalid(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        dirp = self.manifest_dir / "adir"
        dirp.mkdir()
        exit_code, _ = self.run_resolve(manifest, source=dirp)
        self.assertEqual(exit_code, EXIT_SOURCE_INVALID)

    def test_12_symlink_source_rejected_by_default(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        real = self.write_source(self.real_payload)
        link = self.manifest_dir / "link.bin"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable on this filesystem")
        exit_code, _ = self.run_resolve(manifest, source=link)
        self.assertEqual(exit_code, EXIT_SOURCE_INVALID)

    def test_28_staging_cleaned_after_success(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        exit_code, _ = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_OK)
        leftovers = [
            p for p in self.vault_root.rglob("*.tmp")
            if p.name.startswith(".resolve-")
        ]
        self.assertEqual(leftovers, [])

    def test_28b_staging_cleaned_after_source_changed(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        calls = {"n": 0}

        def flaky(path):
            calls["n"] += 1
            if calls["n"] == 3:
                return sha256b(b"changed")
            return resolver.sha256_file(path)

        resolver.HASH_FILE_HOOK = flaky
        exit_code, _ = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_SOURCE_CHANGED)
        leftovers = [
            p for p in self.vault_root.rglob("*.tmp")
            if p.name.startswith(".resolve-")
        ]
        self.assertEqual(leftovers, [])


# ===========================================================================
# Section C: manifest strict validation
# ===========================================================================

class ManifestValidationTests(ResolverTestCase):
    def test_13_malformed_manifest(self):
        p = self.manifest_dir / "bad.json"
        p.write_text("{ not json !!!", encoding="utf-8")
        with self.assertRaises(resolver.ResolverError) as ctx:
            resolver.validate_manifest(p, "gto_launcher")
        self.assertEqual(ctx.exception.exit_code, EXIT_MANIFEST_INVALID)

    def test_14_duplicate_key(self):
        dup_json = (
            '{"schema_version":"mida.case-manifest/v2",'
            '"schema_version":"x",'
            '"case_id":"gto_launcher","manifest_revision":1}'
        )
        p = self.manifest_dir / "dup.json"
        p.write_text(dup_json, encoding="utf-8")
        with self.assertRaises(resolver.ResolverError) as ctx:
            resolver.validate_manifest(p, "gto_launcher")
        self.assertEqual(ctx.exception.exit_code, EXIT_MANIFEST_INVALID)

    def test_15_unknown_schema(self):
        manifest = make_manifest(
            payload_sha=self.payload_sha, size=self.payload_size,
            schema_version="mida.case-manifest/v3",
        )
        with self.assertRaises(resolver.ResolverError) as ctx:
            resolver.validate_manifest(self.write_manifest(manifest), "gto_launcher")
        self.assertEqual(ctx.exception.exit_code, EXIT_MANIFEST_INVALID)

    def test_16_missing_protected_input(self):
        manifest = make_manifest(
            payload_sha=self.payload_sha, size=self.payload_size, n_protected=0
        )
        with self.assertRaises(resolver.ResolverError) as ctx:
            resolver.validate_manifest(self.write_manifest(manifest), "gto_launcher")
        self.assertEqual(ctx.exception.exit_code, EXIT_MANIFEST_INVALID)

    def test_17_two_protected_inputs(self):
        manifest = make_manifest(
            payload_sha=self.payload_sha, size=self.payload_size, n_protected=2
        )
        with self.assertRaises(resolver.ResolverError) as ctx:
            resolver.validate_manifest(self.write_manifest(manifest), "gto_launcher")
        self.assertEqual(ctx.exception.exit_code, EXIT_MANIFEST_INVALID)

    def test_18_three_sha_inconsistent(self):
        # primary differs from protected
        other = sha256b(b"OTHER")
        manifest = make_manifest(
            payload_sha=self.payload_sha, size=self.payload_size, primary_sha=other
        )
        with self.assertRaises(resolver.ResolverError) as ctx:
            resolver.validate_manifest(self.write_manifest(manifest), "gto_launcher")
        self.assertEqual(ctx.exception.exit_code, EXIT_MANIFEST_INVALID)
        # fixed differs from protected
        manifest2 = make_manifest(
            payload_sha=self.payload_sha, size=self.payload_size, fixed_sha=other
        )
        with self.assertRaises(resolver.ResolverError) as ctx:
            resolver.validate_manifest(self.write_manifest(manifest2), "gto_launcher")
        self.assertEqual(ctx.exception.exit_code, EXIT_MANIFEST_INVALID)

    def test_19_size_type_rejected(self):
        for bad in ["8583680", 8583680.0, True]:
            manifest = make_manifest(
                payload_sha=self.payload_sha, size=self.payload_size, size_val=bad
            )
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.validate_manifest(self.write_manifest(manifest), "gto_launcher")
            self.assertEqual(ctx.exception.exit_code, EXIT_MANIFEST_INVALID)


# ===========================================================================
# Section D: resolution record integrity
# ===========================================================================

class RecordIntegrityTests(ResolverTestCase):
    def test_22_success_record_self_consistent(self):
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, _ = self.run_resolve(manifest)
        self.assertEqual(exit_code, EXIT_OK)
        rec = self.read_record()
        self.assertIsNotNone(rec)
        self.assertEqual(rec["schema_version"], "mida.resolved-source/v1")
        self.assertTrue(rec["revision_match"])
        self.assertEqual(rec["resolution_status"], "ResolvedAuthorizedRevision")
        self.assertTrue(rec["vault_object_verified"])
        self.assertTrue(rec["resolved_vault_path"])
        self.assertEqual(rec["expected_sha256"], self.payload_sha)
        self.assertEqual(rec["expected_size_bytes"], self.payload_size)
        self.assertIsNotNone(rec["resolved_utc"])
        self.assertTrue(rec["resolver_tool_sha256"])

    def test_23_failure_record_never_claims_match(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(b"WRONG-HASH-" + b"\x00" * 40)
        exit_code, _ = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_SAMPLE_MISMATCH)
        rec = self.read_record()
        self.assertIsNotNone(rec)
        self.assertFalse(rec["revision_match"])
        self.assertFalse(rec["vault_object_verified"])
        self.assertEqual(rec["resolution_status"], "SampleIdentityMismatch")
        # mutable locator was read -> stability true, but not a match
        self.assertTrue(rec["source_stable_during_snapshot"])
        self.assertEqual(rec["resolved_vault_path"], None)

    def test_24_atomic_no_partial_file(self):
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, _ = self.run_resolve(manifest)
        self.assertEqual(exit_code, EXIT_OK)
        # No .tmp leftovers next to the record.
        leftovers = [p for p in self.evidence.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_29_output_deterministic(self):
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        self.run_resolve(manifest)
        rec1 = self.read_record()
        self.run_resolve(manifest)
        rec2 = self.read_record()
        # Remove time-bearing fields for determinism comparison.
        k = "resolved_utc"
        self.assertEqual(
            {kk: v for kk, v in rec1.items() if kk != k},
            {kk: v for kk, v in rec2.items() if kk != k},
        )

    def test_26_resolver_does_not_execute_pe(self):
        # The resolver never invokes CreateProcess / never runs the payload.
        # We assert the resolved record points at a synthetic blob that is never
        # started. The core has no subprocess execution path; confirm by scanning.
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, result = self.run_resolve(manifest)
        self.assertEqual(exit_code, EXIT_OK)
        # `subprocess` must not appear in the core source.
        core_src = CORE_PY.read_text(encoding="utf-8")
        self.assertNotIn("subprocess", core_src)
        self.assertNotIn("Popen", core_src)
        self.assertNotIn("CreateProcess", core_src)

    def test_27_unicode_and_spaces_in_paths(self):
        # Directory with a space and a Unicode name.
        spaced = Path(self.temp.name) / "有 空 格 dir"
        spaced.mkdir()
        ev = spaced / "evidence dir"
        ev.mkdir()
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = spaced / "名 字 manifest.json"
        mpath.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        vroot = spaced / "vault root"
        vroot.mkdir()
        vp = resolver.vault_object_path(vroot, self.payload_sha)
        vp.parent.mkdir(parents=True, exist_ok=True)
        vp.write_bytes(self.real_payload)
        try:
            result = resolver.resolve(
                manifest_path=mpath,
                case_id="gto_launcher",
                vault_root=vroot,
                evidence_dir=ev,
                source_path=None,
                force_acquire=False,
                retain_unmatched=False,
                observed_revisions_dir=self.observed,
            )
        except resolver.ResolverError as exc:
            self.fail(f"unicode path failed: {exc.detail}")
        self.assertTrue(result["revision_match"])
        self.assertTrue((ev / "resolved_source.json").exists())


# ===========================================================================
# Section E: entry points / wrapper exit-code preservation
# ===========================================================================

class EntryPointTests(ResolverTestCase):
    def test_main_returns_exit_code_via_cli(self):
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = self.write_manifest(manifest)
        code = resolver.main(
            [
                "--ManifestPath", str(mpath),
                "--VaultRoot", str(self.vault_root),
                "--EvidenceDir", str(self.evidence),
                "--CaseId", "gto_launcher",
            ]
        )
        self.assertEqual(code, EXIT_OK)

    def test_main_vault_corrupt_exit(self):
        self.seed_vault(b"\x00" * self.payload_size)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = self.write_manifest(manifest)
        code = resolver.main(
            [
                "--ManifestPath", str(mpath),
                "--VaultRoot", str(self.vault_root),
                "--EvidenceDir", str(self.evidence),
                "--CaseId", "gto_launcher",
            ]
        )
        self.assertEqual(code, EXIT_VAULT_CORRUPT)

    def test_cli_subprocess_returns_correct_code(self):
        # Run the core as a subprocess to verify the real exit code flows out.
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = self.write_manifest(manifest)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT / "tools")
        proc = subprocess.run(
            [
                sys.executable, str(CORE_PY),
                "--ManifestPath", str(mpath),
                "--VaultRoot", str(self.vault_root),
                "--EvidenceDir", str(self.evidence),
                "--CaseId", "gto_launcher",
            ],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, EXIT_OK)

    def test_25_wrapper_preserves_exit_code(self):
        # Verify the PowerShell wrapper preserves the Python core exit code.
        if not WRAPPER_PS1.exists():
            self.skipTest("wrapper not present")
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = self.write_manifest(manifest)
        ps = shutil_which("powershell")
        if ps is None:
            self.skipTest("powershell not found")
        cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(WRAPPER_PS1),
            "-ManifestPath", str(mpath),
            "-VaultRoot", str(self.vault_root),
            "-EvidenceDir", str(self.evidence),
            "-CaseId", "gto_launcher",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, EXIT_OK)
        self.assertTrue((self.evidence / "resolved_source.json").exists())


def shutil_which(name):
    import shutil

    return shutil.which(name)


# ===========================================================================
# Section F: retention of unmatched (non-promoting)
# ===========================================================================

class RetentionTests(ResolverTestCase):
    def test_retain_unmatched_archives_not_promotes(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        unmatched = b"NEW-REVISION-" + b"\x00" * 30
        source = self.write_source(unmatched)
        exit_code, _ = self.run_resolve(
            manifest, source=source, retain_unmatched=True, observed_dir=self.observed
        )
        self.assertEqual(exit_code, EXIT_SAMPLE_MISMATCH)
        sha = sha256b(unmatched)
        archived = self.observed / sha[:2] / sha / "artifact.exe"
        self.assertTrue(archived.exists(), "unmatched should be archived")
        self.assertEqual(resolver.sha256_file(archived), sha)
        # Must NOT be promoted into the authorized vault.
        self.assertFalse(
            resolver.vault_object_path(self.vault_root, self.payload_sha).exists()
        )


if __name__ == "__main__":
    unittest.main()
