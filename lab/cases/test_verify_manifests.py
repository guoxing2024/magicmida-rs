from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "v2" / "case-manifest.schema.json"
sys.path.insert(0, str(HERE))

import verify_manifests  # noqa: E402


class ManifestVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.manifest_dir = root / "manifests"
        self.objects_root = root / "objects"
        self.manifest_dir.mkdir()
        self.objects_root.mkdir()
        shutil.copyfile(SCHEMA, self.manifest_dir / SCHEMA.name)

        self.primary_sha = self.add_object(b"primary fixture")
        self.manifest = {
            "$schema": "./case-manifest.schema.json",
            "schema_version": "mida.case-manifest/v2",
            "manifest_revision": 1,
            "case_id": "fixture",
            "display_name": "Verifier fixture",
            "primary_artifact_sha256": self.primary_sha,
            "artifacts": [
                {
                    "sha256": self.primary_sha,
                    "size_bytes": len(b"primary fixture"),
                    "role": "protected_input",
                }
            ],
            "capability_cell": {
                "platform": "windows",
                "binary_format": "pe",
                "architecture": "x86",
                "execution_model": "native",
                "protection_family": "unknown",
                "engine_route": "out_of_scope",
                "corpus_role": "research",
            },
            "static_fingerprint": {
                "artifact_sha256": self.primary_sha,
                "evidence_basis": "direct_header_parse",
                "pe_kind": "PE32",
                "coff_machine": "0x014c",
                "image_base": "0x400000",
                "entry_rva": "0x1000",
                "entry_section": ".text",
                "section_count": 1,
                "import_descriptor_count": 0,
                "has_tls": False,
                "has_relocations": False,
                "observed_markers": ["AHK/GTO"],
            },
            "execution_policy": {
                "dynamic": {
                    "mode": "explicit_authorization_required",
                    "fixed_sha256": self.primary_sha,
                    "timeout_seconds": 120,
                    "process_tree_accounting_required": True,
                },
                "network": {
                    "mode": "deny_all",
                    "network_actions_allowed": False,
                    "isolation_evidence_required": True,
                },
            },
            "oracle": {
                "oracle_id": None,
                "kind": "none",
                "artifact_sha256": None,
                "authority": "none",
                "use": "none",
            },
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def add_object(self, content: bytes) -> str:
        sha256 = hashlib.sha256(content).hexdigest()
        path = self.objects_root / sha256[:2] / sha256
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return sha256

    def run_manifest(self, manifest: dict) -> tuple[dict, int]:
        path = self.manifest_dir / "fixture.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return verify_manifests.verify(self.manifest_dir, self.objects_root)

    def assert_rejected(self, manifest: dict, expected_kind: str) -> None:
        report, exit_code = self.run_manifest(manifest)
        self.assertNotEqual(exit_code, 0, report)
        self.assertIn(expected_kind, {error["kind"] for error in report["errors"]})

    def forbidden_policy(self) -> dict:
        manifest = copy.deepcopy(self.manifest)
        manifest["execution_policy"]["dynamic"] = {
            "mode": "forbidden",
            "fixed_sha256": None,
            "timeout_seconds": None,
            "process_tree_accounting_required": True,
        }
        manifest["execution_policy"]["network"][
            "isolation_evidence_required"
        ] = False
        return manifest

    def test_valid_manifest_allows_ahk_gto_text(self) -> None:
        report, exit_code = self.run_manifest(self.manifest)
        self.assertEqual(exit_code, 0, report)

    def test_holdout_corpus_role_allowed(self) -> None:
        """R3-path-B: corpus_role=holdout is a valid schema enum value."""
        manifest = copy.deepcopy(self.manifest)
        manifest["capability_cell"]["corpus_role"] = "holdout"
        report, exit_code = self.run_manifest(manifest)
        self.assertEqual(exit_code, 0, report)

    def test_explicit_policy_variants_fail_closed(self) -> None:
        variants = []

        fixed = copy.deepcopy(self.manifest)
        fixed["execution_policy"]["dynamic"]["fixed_sha256"] = "0" * 64
        variants.append((fixed, "dynamic_fixed_sha_mismatch"))

        timeout = copy.deepcopy(self.manifest)
        timeout["execution_policy"]["dynamic"]["timeout_seconds"] = None
        variants.append((timeout, "manifest_schema_invalid"))

        accounting = copy.deepcopy(self.manifest)
        accounting["execution_policy"]["dynamic"][
            "process_tree_accounting_required"
        ] = False
        variants.append((accounting, "manifest_schema_invalid"))

        isolation = copy.deepcopy(self.manifest)
        isolation["execution_policy"]["network"][
            "isolation_evidence_required"
        ] = False
        variants.append((isolation, "manifest_schema_invalid"))

        for manifest, expected_kind in variants:
            with self.subTest(expected_kind=expected_kind):
                self.assert_rejected(manifest, expected_kind)

    def test_forbidden_policy_variants_fail_closed(self) -> None:
        variants = []

        fixed = self.forbidden_policy()
        fixed["execution_policy"]["dynamic"]["fixed_sha256"] = self.primary_sha
        variants.append(fixed)

        timeout = self.forbidden_policy()
        timeout["execution_policy"]["dynamic"]["timeout_seconds"] = 120
        variants.append(timeout)

        accounting = self.forbidden_policy()
        accounting["execution_policy"]["dynamic"][
            "process_tree_accounting_required"
        ] = False
        variants.append(accounting)

        isolation = self.forbidden_policy()
        isolation["execution_policy"]["network"][
            "isolation_evidence_required"
        ] = True
        variants.append(isolation)

        for manifest in variants:
            with self.subTest(dynamic=manifest["execution_policy"]):
                self.assert_rejected(manifest, "manifest_schema_invalid")

    def test_architecture_fingerprint_mismatch_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["capability_cell"]["architecture"] = "x86_64"
        self.assert_rejected(manifest, "architecture_fingerprint_mismatch")

    def test_fingerprint_must_reference_primary(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["static_fingerprint"]["artifact_sha256"] = "0" * 64
        self.assert_rejected(manifest, "fingerprint_primary_sha_mismatch")

    def test_oracle_kind_must_match_artifact_role(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        oracle_content = b"oracle fixture"
        oracle_sha = self.add_object(oracle_content)
        manifest["artifacts"].append(
            {
                "sha256": oracle_sha,
                "size_bytes": len(oracle_content),
                "role": "analysis_reference",
            }
        )
        manifest["oracle"] = {
            "oracle_id": "fixture.oracle.v1",
            "kind": "legacy_oracle_candidate",
            "artifact_sha256": oracle_sha,
            "authority": "historical_operator_report",
            "use": "comparison_only",
        }
        self.assert_rejected(manifest, "oracle_artifact_role_mismatch")

    def test_self_certification_terms_are_rejected(self) -> None:
        terms = (
            "accepted",
            "perfect",
            "recovery_level",
            "verified",
            "production_ready",
            "unpack_complete",
        )
        for term in terms:
            manifest = copy.deepcopy(self.manifest)
            manifest["display_name"] = term
            with self.subTest(term=term):
                self.assert_rejected(manifest, "forbidden_self_claim")

    def test_path_variants_are_rejected(self) -> None:
        paths = (
            r"D:\old\sample.exe",
            r"\\server\share\sample.exe",
            r"D:relative\sample.exe",
            "/tmp/sample.exe",
            "runtime_triage/session/sample.exe",
            "cases/origin_macro/sample.exe",
            "archive/runtime_triage/session/sample.exe",
            r"archive\cases\origin_macro\sample.exe",
        )
        for value in paths:
            manifest = copy.deepcopy(self.manifest)
            manifest["display_name"] = value
            with self.subTest(value=value):
                self.assert_rejected(manifest, "forbidden_path_reference")


if __name__ == "__main__":
    unittest.main()
