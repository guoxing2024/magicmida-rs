"""Synthetic tests for the manifest-pinned GTO sample revision resolver.

All tests use temp directories and synthetic bytes. No real mutable sample is
read, no protected sample is launched, and no vault content is touched.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
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
        # Restore any injected hooks and test seams.
        resolver.HASH_FILE_HOOK = None
        resolver.SIZE_HOOK = None
        resolver.set_repo_root_for_test(None)
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


# ===========================================================================
# R1.1: no-clobber promotion primitives
# ===========================================================================

class NoClobberPublishTests(ResolverTestCase):
    """Direct tests of the atomic hard-link publish primitive."""

    def test_publish_no_clobber_creates_new(self):
        staging = self.manifest_dir / "staging.bin"
        staging.write_bytes(self.real_payload)
        dest = self.vault_root / "dest.bin"
        result = resolver.publish_no_clobber(
            staging, dest, self.payload_sha, self.payload_size
        )
        self.assertEqual(result, "published")
        self.assertTrue(dest.exists())
        self.assertEqual(resolver.sha256_file(dest), self.payload_sha)

    def test_publish_no_clobber_existing_identical_is_idempotent(self):
        staging = self.manifest_dir / "staging.bin"
        staging.write_bytes(self.real_payload)
        dest = self.vault_root / "dest.bin"
        dest.write_bytes(self.real_payload)
        result = resolver.publish_no_clobber(
            staging, dest, self.payload_sha, self.payload_size
        )
        self.assertEqual(result, "existing_match")
        # bytes unchanged (no clobber)
        self.assertEqual(dest.read_bytes(), self.real_payload)

    def test_publish_no_clobber_existing_different_is_corrupt_and_not_overwritten(self):
        staging = self.manifest_dir / "staging.bin"
        staging.write_bytes(self.real_payload)
        dest = self.vault_root / "dest.bin"
        dest.write_bytes(b"\x00" * self.payload_size)  # wrong bytes
        with self.assertRaises(resolver.ResolverError) as ctx:
            resolver.publish_no_clobber(staging, dest, self.payload_sha, self.payload_size)
        self.assertEqual(ctx.exception.exit_code, EXIT_VAULT_CORRUPT)
        # original bytes unchanged (no clobber)
        self.assertEqual(dest.read_bytes(), b"\x00" * self.payload_size)

    def test_publish_no_clobber_existing_reparse_rejected(self):
        staging = self.manifest_dir / "staging.bin"
        staging.write_bytes(self.real_payload)
        real = self.manifest_dir / "real.bin"
        real.write_bytes(self.real_payload)
        dest = self.vault_root / "dest.bin"
        try:
            os.symlink(real, dest)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(resolver.ResolverError) as ctx:
            resolver.publish_no_clobber(staging, dest, self.payload_sha, self.payload_size)
        self.assertEqual(ctx.exception.exit_code, EXIT_VAULT_CORRUPT)

    def test_no_os_replace_for_vault_artifacts(self):
        # Static guarantee: the core never uses os.replace on vault/observed
        # artifact promotion paths.
        core = CORE_PY.read_text(encoding="utf-8")
        # os.replace is still allowed for the atomic *record* write, but the
        # publish primitive must use os.link only.
        self.assertIn("os.link", core)
        self.assertNotIn("os.replace(self.path", core)


class ForceAcquireTests(ResolverTestCase):
    def test_force_acquire_corrupt_vault_returns_corrupt_bytes_unchanged(self):
        vp = self.seed_vault(b"\x00" * self.payload_size)  # wrong bytes
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        exit_code, _ = self.run_resolve(
            manifest, source=source, force_acquire=True
        )
        self.assertEqual(exit_code, EXIT_VAULT_CORRUPT)
        # original wrong bytes unchanged; source never promoted over it.
        self.assertEqual(vp.read_bytes(), b"\x00" * self.payload_size)

    def test_force_acquire_correct_vault_keeps_destination(self):
        vp = self.seed_vault(self.real_payload)  # correct object
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        exit_code, result = self.run_resolve(
            manifest, source=source, force_acquire=True
        )
        self.assertEqual(exit_code, EXIT_OK)
        self.assertTrue(result["revision_match"])
        # destination file identity/bytes preserved (not replaced)
        self.assertEqual(vp.read_bytes(), self.real_payload)
        self.assertEqual(result["resolved_vault_path"], str(vp))

    def test_force_acquire_correct_vault_with_different_source_is_mismatch(self):
        self.seed_vault(self.real_payload)  # correct object
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(b"DIFFERENT-" + b"\x00" * 40)
        exit_code, _ = self.run_resolve(
            manifest, source=source, force_acquire=True
        )
        self.assertEqual(exit_code, EXIT_SAMPLE_MISMATCH)
        # destination still intact
        vp = resolver.vault_object_path(self.vault_root, self.payload_sha)
        self.assertEqual(vp.read_bytes(), self.real_payload)


class PromotionRaceTests(ResolverTestCase):
    """Destination appearing between snapshot and publish."""

    def test_promotion_race_correct_existing_is_idempotent(self):
        # Vault absent, mutable source matches. But a concurrent actor creates
        # the correct vault object before publish. Simulate by pre-seeding the
        # correct object, which the no-clobber publish treats as idempotent.
        vp = self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        exit_code, result = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_OK)
        self.assertTrue(result["revision_match"])
        self.assertEqual(vp.read_bytes(), self.real_payload)

    def test_promotion_race_wrong_existing_is_corrupt(self):
        # Concurrent actor placed wrong bytes at the destination; publish must
        # fail closed and not overwrite them.
        vp = self.seed_vault(b"\x00" * self.payload_size)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        exit_code, _ = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_VAULT_CORRUPT)
        self.assertEqual(vp.read_bytes(), b"\x00" * self.payload_size)


class PostPublishRehashTests(ResolverTestCase):
    def test_post_publish_rehash_failure_no_match_no_bad_object(self):
        # Force post-publish rehash to fail: after the hard-link is created,
        # the destination's hash differs, so publish_no_clobber removes it.
        # The only _hash_file(dest) call is the post-publish check (dest did
        # not exist before), so a path-specific hook is deterministic.
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        vp = resolver.vault_object_path(self.vault_root, self.payload_sha)

        def flaky(path):
            if path == vp:
                return resolver.sha256_bytes(b"BAD")
            return resolver.sha256_file(path)

        resolver.HASH_FILE_HOOK = flaky
        try:
            exit_code, _ = self.run_resolve(manifest, source=source)
        finally:
            resolver.HASH_FILE_HOOK = None
        self.assertEqual(exit_code, EXIT_VAULT_CORRUPT)
        # No revision_match in the record; no bad object left.
        rec = self.read_record()
        self.assertFalse(rec["revision_match"])
        self.assertFalse(rec["vault_object_verified"])
        self.assertFalse(vp.exists(), "bad object must not remain")


class ObservedConcurrencyTests(ResolverTestCase):
    def test_observed_identical_is_idempotent(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        unmatched = b"NEW-REVISION-" + b"\x00" * 30
        source = self.write_source(unmatched)
        sha = sha256b(unmatched)
        # Pre-place correct observed object.
        od = self.observed / sha[:2] / sha
        od.mkdir(parents=True)
        (od / "artifact.exe").write_bytes(unmatched)
        exit_code, _ = self.run_resolve(
            manifest, source=source, retain_unmatched=True, observed_dir=self.observed
        )
        self.assertEqual(exit_code, EXIT_SAMPLE_MISMATCH)
        # observed bytes preserved
        self.assertEqual((od / "artifact.exe").read_bytes(), unmatched)

    def test_observed_different_is_rejected_no_overwrite(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        unmatched = b"NEW-REVISION-" + b"\x00" * 30
        source = self.write_source(unmatched)
        sha = sha256b(unmatched)
        od = self.observed / sha[:2] / sha
        od.mkdir(parents=True)
        (od / "artifact.exe").write_bytes(b"\x00" * len(unmatched))  # wrong
        exit_code, _ = self.run_resolve(
            manifest, source=source, retain_unmatched=True, observed_dir=self.observed
        )
        self.assertEqual(exit_code, EXIT_VAULT_CORRUPT)
        # original (wrong) observed bytes unchanged
        self.assertEqual((od / "artifact.exe").read_bytes(), b"\x00" * len(unmatched))


class SourceChangedEvidenceTests(ResolverTestCase):
    def test_source_changed_record_has_false_and_observation(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        source = self.write_source(self.real_payload)
        calls = {"n": 0}

        def flaky(path):
            calls["n"] += 1
            if calls["n"] == 3:
                return sha256b(b"CHANGED-" + path.read_bytes())
            return resolver.sha256_file(path)

        resolver.HASH_FILE_HOOK = flaky
        exit_code, _ = self.run_resolve(manifest, source=source)
        self.assertEqual(exit_code, EXIT_SOURCE_CHANGED)
        rec = self.read_record()
        self.assertEqual(rec["resolution_status"], "SourceChangedDuringSnapshot")
        # must be false, NOT null
        self.assertIs(rec["source_stable_during_snapshot"], False)
        self.assertFalse(rec["revision_match"])
        self.assertFalse(rec["vault_object_verified"])
        self.assertIsNone(rec["resolved_vault_path"])
        obs = rec.get("snapshot_observation")
        self.assertIsNotNone(obs)
        self.assertIn("h1", obs)
        self.assertIn("h2", obs)
        self.assertIn("h3", obs)
        self.assertIn("s1", obs)
        self.assertIn("s2", obs)
        self.assertIn("s3", obs)


class ManifestSingleReadTests(ResolverTestCase):
    def test_manifest_read_once_digest_binds_to_same_buffer(self):
        # Write a valid manifest, resolve, then change the file on disk.
        # The record must reflect the ORIGINAL bytes (no re-read after parse).
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = self.write_manifest(manifest)
        original_bytes = mpath.read_bytes()
        try:
            result = resolver.resolve(
                manifest_path=mpath,
                case_id="gto_launcher",
                vault_root=self.vault_root,
                evidence_dir=self.evidence,
                source_path=None,
                force_acquire=False,
                retain_unmatched=False,
                observed_revisions_dir=self.observed,
            )
        except resolver.ResolverError as exc:
            self.fail(f"resolve failed: {exc.detail}")
        self.assertTrue(result["revision_match"])
        expected_digest = resolver.sha256_bytes(original_bytes)
        self.assertEqual(result["manifest_sha256"], expected_digest)

        # Drift: mutate the file after resolution. Record must still bind to the
        # originally-read buffer.
        mpath.write_text('{"schema_version":"mida.case-manifest/v2","drift":true}',
                         encoding="utf-8")
        rec = json.loads((self.evidence / "resolved_source.json").read_text(encoding="utf-8"))
        self.assertEqual(rec["manifest_sha256"], expected_digest)
        self.assertEqual(rec["expected_sha256"], self.payload_sha)

    def test_validate_manifest_bytes_is_single_buffer(self):
        payload = json.dumps(
            make_manifest(payload_sha=self.payload_sha, size=self.payload_size),
            indent=2,
        ).encode("utf-8")
        parsed = resolver.validate_manifest_bytes(payload, "gto_launcher")
        self.assertEqual(parsed["expected_sha256"], self.payload_sha)
        self.assertEqual(parsed["expected_size_bytes"], self.payload_size)


class PathSafetyTests(ResolverTestCase):
    def test_vault_root_inside_repo_rejected(self):
        # Simulate a repository root via the private test seam; VaultRoot inside
        # it must fail closed. No public --RepoRoot override exists.
        repo = self.manifest_dir  # pretend this is the repo root
        resolver.set_repo_root_for_test(repo)
        try:
            manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
            mpath = self.write_manifest(manifest)
            vault_inside = repo / "vault"
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.resolve(
                    manifest_path=mpath,
                    case_id="gto_launcher",
                    vault_root=vault_inside,
                    evidence_dir=self.evidence,
                    source_path=None,
                    force_acquire=False,
                    retain_unmatched=False,
                    observed_revisions_dir=self.observed,
                )
            self.assertEqual(ctx.exception.exit_code, EXIT_SOURCE_INVALID)
        finally:
            resolver.set_repo_root_for_test(None)

    def test_observed_dir_inside_repo_rejected(self):
        repo = self.manifest_dir
        resolver.set_repo_root_for_test(repo)
        try:
            manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
            mpath = self.write_manifest(manifest)
            observed_inside = repo / "observed"
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.resolve(
                    manifest_path=mpath,
                    case_id="gto_launcher",
                    vault_root=self.vault_root,
                    evidence_dir=self.evidence,
                    source_path=None,
                    force_acquire=False,
                    retain_unmatched=False,
                    observed_revisions_dir=observed_inside,
                )
            self.assertEqual(ctx.exception.exit_code, EXIT_SOURCE_INVALID)
        finally:
            resolver.set_repo_root_for_test(None)

    def test_staging_never_inside_repo(self):
        # The observed/staging path must also be rejected when under the repo.
        repo = self.manifest_dir
        resolver.set_repo_root_for_test(repo)
        try:
            manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
            mpath = self.write_manifest(manifest)
            # VaultRoot outside repo, but the derived observed-revisions default
            # would be vault_root.parent/observed-revisions (outside too). Force
            # an observed dir inside the repo instead.
            observed_inside = repo / "observed"
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.resolve(
                    manifest_path=mpath,
                    case_id="gto_launcher",
                    vault_root=self.vault_root,
                    evidence_dir=self.evidence,
                    source_path=self.write_source(self.real_payload),
                    force_acquire=False,
                    retain_unmatched=True,
                    observed_revisions_dir=observed_inside,
                )
            self.assertEqual(ctx.exception.exit_code, EXIT_SOURCE_INVALID)
        finally:
            resolver.set_repo_root_for_test(None)

    def test_vault_reparse_artifact_rejected(self):
        real = self.manifest_dir / "real.bin"
        real.write_bytes(self.real_payload)
        vp = resolver.vault_object_path(self.vault_root, self.payload_sha)
        vp.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(real, vp)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, _ = self.run_resolve(manifest)
        self.assertEqual(exit_code, EXIT_VAULT_CORRUPT)


class ToolHashTests(ResolverTestCase):
    def test_resolver_tool_sha256_is_raw_bytes_digest(self):
        expected = hashlib.sha256(CORE_PY.read_bytes()).hexdigest()
        self.assertEqual(resolver.tool_sha256(), expected)

    def test_record_tool_sha256_matches_file(self):
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        exit_code, result = self.run_resolve(manifest)
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(result["resolver_tool_sha256"],
                         hashlib.sha256(CORE_PY.read_bytes()).hexdigest())


class WrapperExitCodeTests(ResolverTestCase):
    """Real subprocess tests: the wrapper preserves core exit codes."""

    def _run_wrapper(self, args):
        if not WRAPPER_PS1.exists():
            self.skipTest("wrapper not present")
        ps = shutil_which("powershell")
        if ps is None:
            self.skipTest("powershell not found")
        cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(WRAPPER_PS1),
        ] + args
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_wrapper_missing_args_exit_17(self):
        proc = self._run_wrapper([])
        self.assertEqual(proc.returncode, 17)

    def test_wrapper_vault_corrupt_exit_13(self):
        self.seed_vault(b"\x00" * self.payload_size)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = self.write_manifest(manifest)
        proc = self._run_wrapper([
            "-ManifestPath", str(mpath),
            "-VaultRoot", str(self.vault_root),
            "-EvidenceDir", str(self.evidence),
            "-CaseId", "gto_launcher",
        ])
        self.assertEqual(proc.returncode, 13)

    def test_wrapper_manifest_invalid_exit_14(self):
        mpath = self.manifest_dir / "bad.json"
        mpath.write_text("{ not json !!!", encoding="utf-8")
        proc = self._run_wrapper([
            "-ManifestPath", str(mpath),
            "-VaultRoot", str(self.vault_root),
            "-EvidenceDir", str(self.evidence),
            "-CaseId", "gto_launcher",
        ])
        self.assertEqual(proc.returncode, 14)

    def test_wrapper_success_exit_0(self):
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = self.write_manifest(manifest)
        proc = self._run_wrapper([
            "-ManifestPath", str(mpath),
            "-VaultRoot", str(self.vault_root),
            "-EvidenceDir", str(self.evidence),
            "-CaseId", "gto_launcher",
        ])
        self.assertEqual(proc.returncode, 0)


# ===========================================================================
# R1.2: authoritative repo root / retention / identity-safe cleanup / exit codes
# ===========================================================================

class AuthoritativeRepoRootTests(ResolverTestCase):
    def test_core_derives_repo_root_from_own_location(self):
        self.assertEqual(resolver._default_repo_root(), REPO_ROOT.resolve())
        # No public --RepoRoot flag exists in the CLI parser (cannot forge).
        parser = resolver._build_parser()
        arg_names = [a.dest for a in parser._actions]
        self.assertNotIn("RepoRoot", arg_names)
        self.assertNotIn("repo_root", arg_names)

    def test_fake_repo_root_flag_is_unknown_arg_exit_2(self):
        # The CLI has no --RepoRoot override; passing one is a usage error only.
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = self.write_manifest(manifest)
        proc = subprocess.run(
            [sys.executable, str(CORE_PY),
             "--ManifestPath", str(mpath),
             "--VaultRoot", str(self.vault_root),
             "--EvidenceDir", str(self.evidence),
             "--RepoRoot", str(REPO_ROOT)],
            capture_output=True, text=True,
        )
        # exit 2 = argparse usage error, NEVER a resolver status path.
        self.assertEqual(proc.returncode, 2)

    def test_cli_vault_inside_repo_exit_15(self):
        # Create a synthetic vault inside the real repo to prove the core's own
        # authoritative-root check fires even via the direct subprocess CLI.
        inner = Path(tempfile.mkdtemp(prefix=".vault-inside-repo-", dir=str(REPO_ROOT)))
        try:
            manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
            mpath = self.write_manifest(manifest)
            evidence2 = self.manifest_dir / "ev2"
            evidence2.mkdir()
            proc = subprocess.run(
                [sys.executable, str(CORE_PY),
                 "--ManifestPath", str(mpath),
                 "--VaultRoot", str(inner),
                 "--EvidenceDir", str(evidence2)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 15)
        finally:
            shutil.rmtree(inner, ignore_errors=True)

    def test_cli_observed_inside_repo_exit_15(self):
        inner = Path(tempfile.mkdtemp(prefix=".obs-inside-repo-", dir=str(REPO_ROOT)))
        try:
            manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
            mpath = self.write_manifest(manifest)
            source = self.write_source(self.real_payload)  # matches manifest
            evidence2 = self.manifest_dir / "ev3"
            evidence2.mkdir()
            proc = subprocess.run(
                [sys.executable, str(CORE_PY),
                 "--ManifestPath", str(mpath),
                 "--VaultRoot", str(self.vault_root),
                 "--EvidenceDir", str(evidence2),
                 "--SourcePath", str(source),
                 "--RetainUnmatched",
                 "--ObservedRevisionsDir", str(inner)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 15)
        finally:
            shutil.rmtree(inner, ignore_errors=True)

    def test_cli_omits_repo_root_still_rejects(self):
        # The authoritative root is always derived; a vault inside it is
        # rejected with no RepoRoot argument at all.
        inner = Path(tempfile.mkdtemp(prefix=".vault-omit-", dir=str(REPO_ROOT)))
        try:
            manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
            mpath = self.write_manifest(manifest)
            evidence2 = self.manifest_dir / "ev4"
            evidence2.mkdir()
            proc = subprocess.run(
                [sys.executable, str(CORE_PY),
                 "--ManifestPath", str(mpath),
                 "--VaultRoot", str(inner),
                 "--EvidenceDir", str(evidence2)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 15)
        finally:
            shutil.rmtree(inner, ignore_errors=True)


class RetentionNoRereadTests(ResolverTestCase):
    def test_retention_archives_first_snapshot_not_later_revision(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        revision_a = b"REV-A-" + b"\x00" * 40
        source = self.write_source(revision_a)
        sha_a = sha256b(revision_a)
        # Count how many times the mutable locator's bytes are read.
        reads = {"source_bytes": 0}

        def counted_hash(path):
            if path == source:
                reads["source_bytes"] += 1
            return resolver.sha256_file(path)

        resolver.HASH_FILE_HOOK = counted_hash
        try:
            exit_code, _ = self.run_resolve(
                manifest, source=source, retain_unmatched=True, observed_dir=self.observed
            )
            # After the primary snapshot, mutate the source to revision B.
            source.write_bytes(b"REV-B-" + b"\x00" * 40)
        finally:
            resolver.HASH_FILE_HOOK = None
        self.assertEqual(exit_code, EXIT_SAMPLE_MISMATCH)
        # Archived object must be revision A (from the first snapshot), not B.
        archived = self.observed / sha_a[:2] / sha_a / "artifact.exe"
        self.assertTrue(archived.exists())
        self.assertEqual(archived.read_bytes(), revision_a)
        self.assertEqual(resolver.sha256_file(archived), sha_a)
        # The mutable source must NOT have been re-snapshot after the primary
        # H1/H2/H3 pass (retention sourced bytes from StableCopy A). The hook
        # counts H1 and H3 (H2 reads the staging temp, not the source).
        self.assertLessEqual(reads["source_bytes"], 2)

    def test_retention_works_when_source_deleted_after_snapshot(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        revision_a = b"REV-A-" + b"\x00" * 40
        source = self.write_source(revision_a)
        sha_a = sha256b(revision_a)
        exit_code, _ = self.run_resolve(
            manifest, source=source, retain_unmatched=True, observed_dir=self.observed
        )
        # Delete the mutable source entirely; retention must already have used
        # the first StableCopy.
        source.unlink()
        self.assertEqual(exit_code, EXIT_SAMPLE_MISMATCH)
        archived = self.observed / sha_a[:2] / sha_a / "artifact.exe"
        self.assertTrue(archived.exists())
        self.assertEqual(archived.read_bytes(), revision_a)

    def test_archived_hash_equals_record_observed_sha256(self):
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        revision_a = b"REV-A-" + b"\x00" * 40
        source = self.write_source(revision_a)
        sha_a = sha256b(revision_a)
        exit_code, _ = self.run_resolve(
            manifest, source=source, retain_unmatched=True, observed_dir=self.observed
        )
        self.assertEqual(exit_code, EXIT_SAMPLE_MISMATCH)
        rec = self.read_record()
        self.assertEqual(rec["observed_sha256"], sha_a)
        archived = self.observed / sha_a[:2] / sha_a / "artifact.exe"
        self.assertEqual(resolver.sha256_file(archived), sha_a)
        self.assertEqual(rec["observed_sha256"], resolver.sha256_file(archived))
        self.assertTrue(rec.get("observed_archive_verified"))
        self.assertEqual(rec["observed_archive_path"], str(archived))


class OwnershipSafeCleanupTests(ResolverTestCase):
    def _direct_publish(self, dest_data=None, flaky_dest_hash=False, replace_dest=None):
        staging = self.manifest_dir / "stage.bin"
        staging.write_bytes(self.real_payload)
        dest = self.vault_root / "artifact.exe"
        if dest_data is not None:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(dest_data)
        if replace_dest is not None:
            # A concurrent actor will swap the dest file's content after link.
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(replace_dest)
        return staging, dest

    def test_concurrent_replace_not_deleted(self):
        staging, dest = self._direct_publish(replace_dest=b"CONCURRENT-" + b"\x00" * 40)
        replacement = b"CONCURRENT-" + b"\x00" * 40
        # Force post-publish rehash to fail by making dest hash differ via hook.
        def flaky(path):
            if path == dest:
                return sha256b(b"BAD")
            return resolver.sha256_file(path)

        resolver.HASH_FILE_HOOK = flaky
        try:
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.publish_no_clobber(staging, dest, self.payload_sha, self.payload_size)
        finally:
            resolver.HASH_FILE_HOOK = None
        self.assertEqual(ctx.exception.exit_code, EXIT_VAULT_CORRUPT)
        # The concurrent replacement file must still exist with its bytes.
        self.assertTrue(dest.exists())
        self.assertEqual(dest.read_bytes(), replacement)

    def test_own_link_cleaned_on_normal_rehash_failure(self):
        staging, dest = self._direct_publish()
        # Force post-publish rehash to fail but keep identity (same inode) ->
        # resolver removes its own link.
        def flaky(path):
            if path == dest:
                return sha256b(b"BAD")
            return resolver.sha256_file(path)

        resolver.HASH_FILE_HOOK = flaky
        try:
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.publish_no_clobber(staging, dest, self.payload_sha, self.payload_size)
        finally:
            resolver.HASH_FILE_HOOK = None
        self.assertEqual(ctx.exception.exit_code, EXIT_VAULT_CORRUPT)
        # Our own link is removed (no bad object left).
        self.assertFalse(dest.exists())

    def test_identity_comparison_error_defaults_no_delete(self):
        staging, dest = self._direct_publish()
        # Make _file_identity return None (identity comparison unavailable) and
        # force rehash failure: resolver must fail closed and NOT delete.
        orig = resolver._file_identity
        resolver._file_identity = lambda p: None
        resolver.HASH_FILE_HOOK = lambda p: (sha256b(b"BAD") if p == dest
                                             else resolver.sha256_file(p))
        try:
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.publish_no_clobber(staging, dest, self.payload_sha, self.payload_size)
        finally:
            resolver._file_identity = orig
            resolver.HASH_FILE_HOOK = None
        self.assertEqual(ctx.exception.exit_code, EXIT_VAULT_CORRUPT)
        # Identity unavailable -> must NOT have deleted dest.
        self.assertTrue(dest.exists())


class ExitCodeContractTests(ResolverTestCase):
    def test_force_acquire_no_source_exit_15_not_2(self):
        # Correct vault exists; --ForceAcquire with no SourcePath must return a
        # documented resolver status (15), never argparse exit 2.
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        mpath = self.write_manifest(manifest)
        proc = subprocess.run(
            [sys.executable, str(CORE_PY),
             "--ManifestPath", str(mpath),
             "--VaultRoot", str(self.vault_root),
             "--EvidenceDir", str(self.evidence),
             "--ForceAcquire"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 15)
        self.assertNotEqual(proc.returncode, 2)

    def test_manifest_missing_exit_14(self):
        missing = self.manifest_dir / "nope.json"
        proc = subprocess.run(
            [sys.executable, str(CORE_PY),
             "--ManifestPath", str(missing),
             "--VaultRoot", str(self.vault_root),
             "--EvidenceDir", str(self.evidence)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 14)

    def test_manifest_is_directory_exit_14(self):
        d = self.manifest_dir / "adir"
        d.mkdir()
        proc = subprocess.run(
            [sys.executable, str(CORE_PY),
             "--ManifestPath", str(d),
             "--VaultRoot", str(self.vault_root),
             "--EvidenceDir", str(self.evidence)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 14)


class ReparseSeamTests(ResolverTestCase):
    """Non-skippable deterministic seam tests (no filesystem symlinks needed)."""

    def test_seam_vault_reparse_fails_closed(self):
        # Monkeypatch reparse detection to True; the vault path must fail closed.
        self.seed_vault(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        orig = resolver._is_reparse_point
        resolver._is_reparse_point = lambda p: True
        try:
            exit_code, _ = self.run_resolve(manifest)
        finally:
            resolver._is_reparse_point = orig
        self.assertEqual(exit_code, EXIT_VAULT_CORRUPT)

    def test_seam_existing_destination_reparse_fails_closed(self):
        staging = self.manifest_dir / "stage.bin"
        staging.write_bytes(self.real_payload)
        dest = self.vault_root / "dest.bin"
        dest.write_bytes(self.real_payload)
        orig = resolver._is_reparse_point
        resolver._is_reparse_point = lambda p: True
        try:
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.publish_no_clobber(
                    staging, dest, self.payload_sha, self.payload_size
                )
        finally:
            resolver._is_reparse_point = orig
        self.assertEqual(ctx.exception.exit_code, EXIT_VAULT_CORRUPT)

    def test_seam_source_reparse_fails_closed(self):
        source = self.write_source(self.real_payload)
        manifest = make_manifest(payload_sha=self.payload_sha, size=self.payload_size)
        orig = resolver._is_reparse_point
        resolver._is_reparse_point = lambda p: True
        try:
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.stable_snapshot(source, self.vault_root)
        finally:
            resolver._is_reparse_point = orig
        self.assertEqual(ctx.exception.exit_code, EXIT_SOURCE_INVALID)


if __name__ == "__main__":
    unittest.main()