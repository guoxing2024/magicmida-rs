# -*- coding: utf-8 -*-
"""Register a third Oreans PE as R3 holdout (operator-provided bytes only).

Does NOT claim R3. Refuses forbidden case_ids and known corpus hashes.
Writes vault CAS object + materialization + lab/cases/v2 manifest draft.

Usage:
  python tools/_register_oreans_holdout.py --pe PATH --case-id my_holdout_id
  python tools/_register_oreans_holdout.py --pe PATH --case-id my_holdout_id --apply

Without --apply: dry-run (hash, PE fingerprint, proposed paths only).
With --apply: write objects + materialized + manifest, run preflight.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
from _r3_corpus import (  # noqa: E402
    FORBIDDEN_HOLDOUT_IDS,
    OBJECTS,
    MAT,
    load_manifests,
    preflight_report,
)

VAULT = Path(r"D:\MidaVault")
MANIFEST_REPO = REPO / "lab" / "cases" / "v2"
MANIFEST_VAULT = VAULT / "manifests" / "cases"
DROP = VAULT / "scratch" / "holdout_drop"

# Known primary hashes already in corpus (cannot re-label as holdout).
KNOWN_CORPUS_SHA = frozenset(
    {
        "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7",  # origin
        "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07",  # lunlun
        "4d5770afdd2f",  # gto prefix check uses full below when known
    }
)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pe_fingerprint(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE (missing MZ)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 >= len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ValueError("not a PE (bad PE signature)")
    coff = e_lfanew + 4
    machine, nsec = struct.unpack_from("<HH", data, coff)
    optsize = struct.unpack_from("<H", data, coff + 16)[0]
    magic = struct.unpack_from("<H", data, coff + 20)[0]
    opt = coff + 20
    if magic == 0x20B:
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe_kind = "PE32+"
        arch = "x86_64" if machine == 0x8664 else f"machine_{machine:#x}"
    elif magic == 0x10B:
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
        pe_kind = "PE32"
        arch = "x86" if machine == 0x14C else f"machine_{machine:#x}"
    else:
        raise ValueError(f"unsupported optional magic {magic:#x}")

    sect = opt + optsize
    names: list[str] = []
    entry_section = None
    for i in range(nsec):
        off = sect + i * 40
        if off + 40 > len(data):
            break
        name = data[off : off + 8].split(b"\x00")[0].decode("latin1", "replace")
        vsize, va = struct.unpack_from("<II", data, off + 8)
        names.append(name)
        if entry_section is None and va <= entry < va + max(vsize, 1):
            entry_section = name

    markers = []
    for n in names:
        low = n.lower().strip()
        if low in (".boot", ".themida", ".winlice") or low.startswith(".winlic"):
            markers.append(f"section:{n}")

    # TLS directory presence (optional header data dir index 9)
    has_tls = False
    has_reloc = False
    try:
        if magic == 0x20B:
            dd = opt + 112
        else:
            dd = opt + 96
        # IMAGE_DIRECTORY_ENTRY_TLS = 9, BASERELOC = 5
        if dd + 10 * 8 <= len(data):
            tls_rva, tls_sz = struct.unpack_from("<II", data, dd + 9 * 8)
            rel_rva, rel_sz = struct.unpack_from("<II", data, dd + 5 * 8)
            has_tls = tls_rva != 0 and tls_sz != 0
            has_reloc = rel_rva != 0 and rel_sz != 0
    except struct.error:
        pass

    # import descriptor count (best-effort)
    import_count = 0
    try:
        if magic == 0x20B:
            dd = opt + 112
        else:
            dd = opt + 96
        imp_rva, imp_sz = struct.unpack_from("<II", data, dd + 1 * 8)
        if imp_rva and imp_sz:
            # map rva -> file roughly via sections
            file_off = None
            for i in range(nsec):
                off = sect + i * 40
                vsize, va, rsize, ro = struct.unpack_from("<IIII", data, off + 8)
                if va <= imp_rva < va + max(vsize, rsize, 1):
                    file_off = ro + (imp_rva - va)
                    break
            if file_off is not None:
                pos = file_off
                while pos + 20 <= len(data) and import_count < 256:
                    fields = struct.unpack_from("<IIIII", data, pos)
                    if all(x == 0 for x in fields):
                        break
                    import_count += 1
                    pos += 20
    except (struct.error, ValueError):
        pass

    oreans_like = any(
        m.lower().replace("section:", "") in (".boot", ".themida", ".winlice")
        or m.lower().startswith("section:.winlic")
        for m in markers
    ) or any(
        n.lower().strip() in (".boot", ".themida", ".winlice")
        or n.lower().strip().startswith(".winlic")
        for n in names
    )

    return {
        "pe_kind": pe_kind,
        "architecture": arch,
        "coff_machine": f"0x{machine:04x}",
        "image_base": f"0x{image_base:x}",
        "entry_rva": f"0x{entry:x}",
        "entry_section": entry_section or "unknown",
        "section_count": nsec,
        "section_names": names,
        "import_descriptor_count": import_count,
        "has_tls": has_tls,
        "has_relocations": has_reloc,
        "observed_markers": markers,
        "oreans_markers_seen": oreans_like,
    }


def existing_primary_hashes() -> set[str]:
    out: set[str] = set(KNOWN_CORPUS_SHA)
    for m in load_manifests():
        sha = m.get("primary_artifact_sha256")
        if sha:
            out.add(sha.lower())
    return out


def build_manifest(case_id: str, sha: str, size: int, fp: dict, display: str) -> dict:
    return {
        "$schema": "./case-manifest.schema.json",
        "schema_version": "mida.case-manifest/v2",
        "manifest_revision": 1,
        "case_id": case_id,
        "display_name": display,
        "primary_artifact_sha256": sha,
        "artifacts": [
            {
                "sha256": sha,
                "size_bytes": size,
                "role": "protected_input",
            }
        ],
        "capability_cell": {
            "platform": "windows",
            "binary_format": "pe",
            "architecture": fp["architecture"]
            if fp["architecture"] in ("x86_64", "x86")
            else "x86_64",
            "execution_model": "native",
            "protection_family": "oreans_candidate",
            "engine_route": "mida_plugin_oreans",
            "corpus_role": "holdout",
        },
        "static_fingerprint": {
            "artifact_sha256": sha,
            "evidence_basis": "retained_static_report",
            "pe_kind": fp["pe_kind"],
            "coff_machine": fp["coff_machine"],
            "image_base": fp["image_base"],
            "entry_rva": fp["entry_rva"],
            "entry_section": fp["entry_section"],
            "section_count": fp["section_count"],
            "import_descriptor_count": fp["import_descriptor_count"],
            "has_tls": fp["has_tls"],
            "has_relocations": fp["has_relocations"],
            "observed_markers": fp["observed_markers"],
        },
        "execution_policy": {
            "dynamic": {
                "mode": "explicit_authorization_required",
                "fixed_sha256": sha,
                "timeout_seconds": 180,
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


def main() -> int:
    ap = argparse.ArgumentParser(description="Register Oreans holdout PE (not R3 claim)")
    ap.add_argument("--pe", required=True, type=Path, help="path to protected PE")
    ap.add_argument(
        "--case-id",
        required=True,
        help="new case id (snake_case; not origin/lunlun/gto/dali/plain)",
    )
    ap.add_argument("--display-name", default="", help="optional display name")
    ap.add_argument(
        "--apply",
        action="store_true",
        help="write CAS + materialize + manifest (default dry-run)",
    )
    ap.add_argument(
        "--force-non-oreans-markers",
        action="store_true",
        help="allow PE without .boot/.themida/.winlice section names (still oreans_candidate)",
    )
    args = ap.parse_args()

    case_id = args.case_id.strip()
    if not case_id or not all(c.isalnum() or c == "_" for c in case_id):
        print("case-id must be alphanumeric/underscore", file=sys.stderr)
        return 2
    if case_id in FORBIDDEN_HOLDOUT_IDS:
        print(
            f"REFUSED: {case_id!r} is forbidden as holdout "
            f"(see lab/cases/v2/HOLDOUT_SLOT.md)",
            file=sys.stderr,
        )
        return 2
    if any(m.get("case_id") == case_id for m in load_manifests()):
        print(f"REFUSED: case_id {case_id!r} already has a manifest", file=sys.stderr)
        return 2

    pe = args.pe.resolve()
    if not pe.is_file():
        print(f"PE not found: {pe}", file=sys.stderr)
        return 2

    data = pe.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    size = len(data)

    if sha in existing_primary_hashes() or any(
        sha.startswith(k) for k in KNOWN_CORPUS_SHA if len(k) < 64
    ):
        # full-hash check primary
        if sha in existing_primary_hashes():
            print(
                f"REFUSED: sha256 already a corpus primary artifact: {sha}",
                file=sys.stderr,
            )
            return 2

    try:
        fp = pe_fingerprint(data)
    except ValueError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2

    if not fp["oreans_markers_seen"] and not args.force_non_oreans_markers:
        print(
            "REFUSED: no Oreans-like section markers (.boot / .themida / .winlice). "
            "If intentional, pass --force-non-oreans-markers (still not an R3 claim).",
            file=sys.stderr,
        )
        print("sections:", fp["section_names"], file=sys.stderr)
        return 2

    display = args.display_name.strip() or f"Holdout {case_id}"
    manifest = build_manifest(case_id, sha, size, fp, display)

    obj = OBJECTS / sha[:2] / sha
    mat = MAT / f"{case_id}__protected_input__{sha[:12]}.bin"
    mf_repo = MANIFEST_REPO / f"{case_id}.json"
    mf_vault = MANIFEST_VAULT / f"{case_id}.json"

    plan = {
        "mode": "apply" if args.apply else "dry-run",
        "case_id": case_id,
        "sha256": sha,
        "size_bytes": size,
        "source_pe": str(pe),
        "object_path": str(obj),
        "materialized_path": str(mat),
        "manifest_repo": str(mf_repo),
        "manifest_vault": str(mf_vault),
        "fingerprint": {k: fp[k] for k in fp if k != "section_names"},
        "section_names": fp["section_names"],
        "oreans_markers_seen": fp["oreans_markers_seen"],
        "r3_gate": False,
        "note": "Registration only. R3 still needs continuous 10x + validation_summary.",
    }
    print(json.dumps(plan, indent=2))

    if not args.apply:
        print(
            "\nDry-run only. Re-run with --apply to write vault object + manifests.",
            flush=True,
        )
        print(
            f"Suggested drop dir (optional): {DROP}",
            flush=True,
        )
        return 0

    # Apply
    OBJECTS.mkdir(parents=True, exist_ok=True)
    obj.parent.mkdir(parents=True, exist_ok=True)
    if not obj.is_file():
        shutil.copy2(pe, obj)
    else:
        # verify hash if exists
        if sha256_file(obj) != sha:
            print(f"CAS collision with different content: {obj}", file=sys.stderr)
            return 2

    MAT.mkdir(parents=True, exist_ok=True)
    if mat.exists():
        mat.unlink()
    try:
        mat.hardlink_to(obj)
    except OSError:
        shutil.copy2(obj, mat)

    MANIFEST_REPO.mkdir(parents=True, exist_ok=True)
    MANIFEST_VAULT.mkdir(parents=True, exist_ok=True)
    text = json.dumps(manifest, indent=2) + "\n"
    mf_repo.write_text(text, encoding="utf-8")
    mf_vault.write_text(text, encoding="utf-8")

    # Evidence note under vault
    note_dir = VAULT / "lab" / "evidence" / case_id
    note_dir.mkdir(parents=True, exist_ok=True)
    note = note_dir / f"holdout_registered_{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.md"
    note.write_text(
        f"# Holdout registration `{case_id}`\n\n"
        f"- sha256: `{sha}`\n"
        f"- size: {size}\n"
        f"- object: `{obj}`\n"
        f"- materialized: `{mat}`\n"
        f"- manifest: `lab/cases/v2/{case_id}.json`\n"
        f"- r3_gate: false (registration only)\n",
        encoding="utf-8",
    )

    print("wrote", mf_repo)
    print("wrote", mf_vault)
    print("wrote", obj)
    print("wrote", mat)
    print("wrote", note)

    # Preflight
    pf = preflight_report()
    print(
        f"preflight holdout_status={pf.get('holdout_status')} "
        f"gate_assets_ready={pf.get('gate_assets_ready')} r3_gate={pf.get('r3_gate')}"
    )
    out_pf = (
        VAULT
        / "lab"
        / "evidence"
        / "_repeat"
        / f"preflight_holdout_{case_id}_{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    )
    out_pf.mkdir(parents=True, exist_ok=True)
    (out_pf / "preflight.json").write_text(
        json.dumps(pf, indent=2) + "\n", encoding="utf-8"
    )
    print("wrote", out_pf / "preflight.json")

    if pf.get("holdout_status") != "ready":
        print(
            "WARN: holdout_status is not ready — check materialization/manifest",
            file=sys.stderr,
        )
        return 1

    print(
        "\nNEXT (still not R3 claim):\n"
        f"  python tools/_case_live_unpack.py {case_id} --tag holdout_smoke\n"
        f"  python tools/_oreans_repeat_smoke.py --require-holdout "
        f"--cases origin_macro,lunlun_software,{case_id} --count 1 --tag holdout_prep\n"
        "  # Only after smoke green, schedule continuous 10x + validation_summary\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
