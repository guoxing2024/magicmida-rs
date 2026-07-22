#!/usr/bin/env python3
"""Fail-closed verifier for SHA-addressed MagicMida case manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


WINDOWS_DRIVE_REFERENCE = re.compile(r"^[A-Za-z]:")
LEGACY_PATH_REFERENCE = re.compile(
    r"(?:^|[\\/\s\"'(<\[])(?:runtime_triage|cases)(?:[\\/]|$)",
    re.IGNORECASE,
)
SELF_CLAIM = re.compile(
    r"(?:^|[^a-z0-9])(?:"
    r"accepted|perfect|recovery[_ -]?level|verified|validated|certified|"
    r"complete(?:d)?|success(?:ful)?|pass(?:ed)?|clean[_ -]?pe|"
    r"(?:production|release)[_ -]?(?:ready|approved)"
    r")(?:$|[^a-z0-9])",
    re.IGNORECASE,
)
ARCHITECTURE_FINGERPRINT = {
    "x86": ("PE32", "0x014c"),
    "x86_64": ("PE32+", "0x8664"),
}
ORACLE_ARTIFACT_ROLE = {
    "legacy_oracle_candidate": "legacy_oracle_candidate",
    "analysis_reference": "analysis_reference",
    "static_fixture_definition": "synthetic_control",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def walk_text(value: Any, location: str = "$"):
    if isinstance(value, dict):
        for key, child in value.items():
            yield f"{location}.<key>", key
            yield from walk_text(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_text(child, f"{location}[{index}]")
    elif isinstance(value, str):
        yield location, value


def is_forbidden_path(value: str) -> bool:
    return (
        WINDOWS_DRIVE_REFERENCE.match(value) is not None
        or value.startswith("/")
        or value.startswith("\\")
        or LEGACY_PATH_REFERENCE.search(value) is not None
    )


def add_error(report: dict[str, Any], kind: str, **details: Any) -> None:
    report["errors"].append({"kind": kind, **details})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "v2",
    )
    parser.add_argument(
        "--objects-root",
        type=Path,
        required=True,
        help="Content store root containing <sha-prefix>/<sha256> objects",
    )
    return parser.parse_args()


def validate_semantics(
    manifest: dict[str, Any], manifest_name: str, report: dict[str, Any]
) -> None:
    primary_sha256 = manifest["primary_artifact_sha256"]
    fingerprint = manifest["static_fingerprint"]
    capability = manifest["capability_cell"]
    expected_pe_kind, expected_machine = ARCHITECTURE_FINGERPRINT[
        capability["architecture"]
    ]
    if (
        fingerprint["pe_kind"] != expected_pe_kind
        or fingerprint["coff_machine"] != expected_machine
    ):
        add_error(
            report,
            "architecture_fingerprint_mismatch",
            manifest=manifest_name,
            architecture=capability["architecture"],
            expected_pe_kind=expected_pe_kind,
            expected_machine=expected_machine,
            actual_pe_kind=fingerprint["pe_kind"],
            actual_machine=fingerprint["coff_machine"],
        )

    if fingerprint["artifact_sha256"] != primary_sha256:
        add_error(
            report,
            "fingerprint_primary_sha_mismatch",
            manifest=manifest_name,
            primary_sha256=primary_sha256,
            fingerprint_sha256=fingerprint["artifact_sha256"],
        )

    dynamic = manifest["execution_policy"]["dynamic"]
    network = manifest["execution_policy"]["network"]
    if dynamic["mode"] == "explicit_authorization_required":
        if dynamic["fixed_sha256"] != primary_sha256:
            add_error(
                report,
                "dynamic_fixed_sha_mismatch",
                manifest=manifest_name,
                primary_sha256=primary_sha256,
                fixed_sha256=dynamic["fixed_sha256"],
            )
        if not isinstance(dynamic["timeout_seconds"], int) or isinstance(
            dynamic["timeout_seconds"], bool
        ) or dynamic["timeout_seconds"] <= 0:
            add_error(
                report,
                "explicit_dynamic_timeout_invalid",
                manifest=manifest_name,
            )
        if dynamic["process_tree_accounting_required"] is not True:
            add_error(
                report,
                "process_tree_accounting_not_required",
                manifest=manifest_name,
            )
        if network["isolation_evidence_required"] is not True:
            add_error(
                report,
                "explicit_dynamic_isolation_not_required",
                manifest=manifest_name,
            )
    elif dynamic["mode"] == "forbidden":
        if dynamic["fixed_sha256"] is not None:
            add_error(
                report,
                "forbidden_dynamic_fixed_sha_present",
                manifest=manifest_name,
            )
        if dynamic["timeout_seconds"] is not None:
            add_error(
                report,
                "forbidden_dynamic_timeout_present",
                manifest=manifest_name,
            )
        if dynamic["process_tree_accounting_required"] is not True:
            add_error(
                report,
                "process_tree_accounting_not_required",
                manifest=manifest_name,
            )
        if network["isolation_evidence_required"] is not False:
            add_error(
                report,
                "forbidden_dynamic_isolation_must_be_false",
                manifest=manifest_name,
            )

    oracle = manifest["oracle"]
    expected_role = ORACLE_ARTIFACT_ROLE.get(oracle["kind"])
    if expected_role is not None:
        actual_role = next(
            (
                artifact["role"]
                for artifact in manifest["artifacts"]
                if artifact["sha256"] == oracle["artifact_sha256"]
            ),
            None,
        )
        if actual_role != expected_role:
            add_error(
                report,
                "oracle_artifact_role_mismatch",
                manifest=manifest_name,
                oracle_kind=oracle["kind"],
                expected_role=expected_role,
                actual_role=actual_role,
            )


def verify(manifest_dir: Path, objects_root: Path) -> tuple[dict[str, Any], int]:
    manifest_dir = manifest_dir.resolve()
    objects_root = objects_root.resolve()
    report: dict[str, Any] = {
        "schema_valid": False,
        "manifests_checked": 0,
        "objects_checked": 0,
        "missing_objects": 0,
        "size_mismatches": 0,
        "hash_mismatches": 0,
        "forbidden_legacy_refs": 0,
        "forbidden_self_claims": 0,
        "dangling_case_refs": 0,
        "dangling_case_ref_details": [],
        "errors": [],
        "overall_ok": False,
    }

    try:
        import jsonschema
    except ImportError as error:
        add_error(report, "validator_dependency_missing", detail=str(error))
        return report, 2

    schema_path = manifest_dir / "case-manifest.schema.json"
    if not schema_path.is_file() or not objects_root.is_dir():
        add_error(
            report,
            "preflight_failed",
            schema_exists=schema_path.is_file(),
            objects_root_exists=objects_root.is_dir(),
        )
        return report, 2

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as error:
        add_error(report, "schema_invalid", detail=str(error))
        return report, 2

    report["schema_valid"] = True
    manifest_paths = sorted(
        path
        for path in manifest_dir.glob("*.json")
        if path.name != schema_path.name
    )
    if not manifest_paths:
        add_error(report, "no_manifests")

    verified_objects: set[str] = set()
    for manifest_path in manifest_paths:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            add_error(
                report,
                "manifest_json_invalid",
                manifest=manifest_path.name,
                detail=str(error),
            )
            continue

        report["manifests_checked"] += 1

        for location, value in walk_text(manifest):
            if is_forbidden_path(value):
                report["forbidden_legacy_refs"] += 1
                add_error(
                    report,
                    "forbidden_path_reference",
                    manifest=manifest_path.name,
                    location=location,
                    value=value,
                )
            if SELF_CLAIM.search(value) is not None:
                report["forbidden_self_claims"] += 1
                add_error(
                    report,
                    "forbidden_self_claim",
                    manifest=manifest_path.name,
                    location=location,
                    value=value,
                )

        schema_errors = sorted(
            validator.iter_errors(manifest), key=lambda error: list(error.path)
        )
        for error in schema_errors:
            add_error(
                report,
                "manifest_schema_invalid",
                manifest=manifest_path.name,
                location="/".join(str(part) for part in error.path),
                detail=error.message,
            )
        if schema_errors:
            continue

        if manifest_path.stem != manifest["case_id"]:
            add_error(
                report,
                "case_id_filename_mismatch",
                manifest=manifest_path.name,
                case_id=manifest["case_id"],
            )

        artifacts = manifest["artifacts"]
        artifact_shas = [artifact["sha256"] for artifact in artifacts]
        if len(artifact_shas) != len(set(artifact_shas)):
            add_error(
                report,
                "duplicate_artifact_sha256",
                manifest=manifest_path.name,
            )

        references = {
            "primary_artifact_sha256": manifest["primary_artifact_sha256"],
            "static_fingerprint.artifact_sha256": manifest["static_fingerprint"][
                "artifact_sha256"
            ],
            "execution_policy.dynamic.fixed_sha256": manifest["execution_policy"][
                "dynamic"
            ]["fixed_sha256"],
            "oracle.artifact_sha256": manifest["oracle"]["artifact_sha256"],
        }
        for location, sha256 in references.items():
            if sha256 is not None and sha256 not in artifact_shas:
                detail = {
                    "manifest": manifest_path.name,
                    "location": location,
                    "sha256": sha256,
                    "reason": "not_declared_in_artifacts",
                }
                report["dangling_case_refs"] += 1
                report["dangling_case_ref_details"].append(detail)
                add_error(report, "dangling_case_ref", **detail)

        validate_semantics(manifest, manifest_path.name, report)

        for artifact in artifacts:
            sha256 = artifact["sha256"]
            object_path = objects_root / sha256[:2] / sha256
            if not object_path.is_file():
                report["missing_objects"] += 1
                detail = {
                    "manifest": manifest_path.name,
                    "location": "artifacts",
                    "sha256": sha256,
                    "reason": "vault_object_missing",
                }
                report["dangling_case_refs"] += 1
                report["dangling_case_ref_details"].append(detail)
                add_error(report, "vault_object_missing", **detail)
                continue

            if object_path.stat().st_size != artifact["size_bytes"]:
                report["size_mismatches"] += 1
                add_error(
                    report,
                    "vault_object_size_mismatch",
                    manifest=manifest_path.name,
                    sha256=sha256,
                    expected=artifact["size_bytes"],
                    actual=object_path.stat().st_size,
                )
                continue

            if sha256 not in verified_objects:
                report["objects_checked"] += 1
                actual_sha256 = sha256_file(object_path)
                if actual_sha256 != sha256:
                    report["hash_mismatches"] += 1
                    add_error(
                        report,
                        "vault_object_hash_mismatch",
                        manifest=manifest_path.name,
                        expected=sha256,
                        actual=actual_sha256,
                    )
                    continue
                verified_objects.add(sha256)

    report["overall_ok"] = not report["errors"]
    return report, 0 if report["overall_ok"] else 1


def main() -> int:
    args = parse_args()
    report, exit_code = verify(args.manifest_dir, args.objects_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
