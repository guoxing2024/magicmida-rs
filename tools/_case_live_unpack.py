# -*- coding: utf-8 -*-
"""Generic vault case live unpack + optional R0B. Evidence under vault only.

Case resolution: built-in Oreans map first, then lab/cases/v2 manifest +
materialized CAS naming (enables future holdout without code edits).

R4-A2: optional `--profile` (e.g. ahk-gto-experimental). Profile is never
inferred from case_id alone — caller must pass it explicitly for GTO stages.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _r3_corpus import load_manifests, resolve_case_cfg  # noqa: E402

CLI = Path(r"D:\MidaVault\scratch\cargo-target\debug\mida-cli.exe")
ACC = Path(r"D:\MidaVault\scratch\cargo-target\debug\mida-acceptance.exe")
MAT = Path(r"D:\MidaVault\scratch\materialized")
EV_ROOT = Path(r"D:\MidaVault\lab\evidence")

# Built-in overrides (stable names used by existing evidence paths).
BUILTIN = {
    "origin_macro": {
        "src": "origin_macro__protected_input__1af62999cf5b.bin",
        "src_note": "origin_macro protected_input 1af62999cf5b",
        "prefix": "origin",
        "oracle": "origin_macro__legacy_oracle_candidate__fe92f992bcf0.bin",
    },
    "lunlun_software": {
        "src": "lunlun_software__protected_input__8a0118d04e03.bin",
        "src_note": "lunlun_software protected_input 8a0118d04e03",
        "prefix": "lunlun",
        "oracle": None,
    },
}

# Known dump profiles (pass-through to mida-cli). Empty = CLI default (OreansClassic).
KNOWN_PROFILES = frozenset(
    {
        "oreans-classic",
        "ahk-gto-experimental",
    }
)

RE_DUAL_SELECT = re.compile(
    r'PackerPlugin identify:\s*dual-family select.*?selected="([^"]+)".*?conf=(\d+)',
    re.I,
)
RE_PLUGIN_MATCH = re.compile(
    r'PackerPlugin identify:\s*Match\s+family="([^"]+)"\s+confidence=(\d+)',
    re.I,
)
RE_STRUCTURE_EP = re.compile(r"Structure gate:\s*EP=(0x[0-9a-fA-F]+)", re.I)
RE_DUMP_FAMILY = re.compile(
    r'PackerPlugin:\s*dump enter.*?family="([^"]+)"',
    re.I,
)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_cfg(case_id: str) -> dict | None:
    if case_id in BUILTIN:
        b = BUILTIN[case_id]
        src = MAT / b["src"]
        if not src.is_file():
            # Fall through to manifest resolution.
            pass
        else:
            oracle = MAT / b["oracle"] if b.get("oracle") else None
            return {
                "case_id": case_id,
                "src": b["src"],
                "src_path": src,
                "src_note": b["src_note"],
                "prefix": b["prefix"],
                "oracle": b.get("oracle"),
                "oracle_path": oracle if oracle and oracle.is_file() else None,
            }
    return resolve_case_cfg(case_id, manifests=load_manifests(), mat=MAT)


def known_case_ids() -> list[str]:
    ids = set(BUILTIN.keys())
    for m in load_manifests():
        cid = m.get("case_id")
        if cid:
            ids.add(cid)
    return sorted(ids)


def parse_unpack_signals(log: str) -> dict:
    """Extract dual-select / structure / dump family from verbose unpack log."""
    selected = None
    conf = None
    m = RE_DUAL_SELECT.search(log)
    if m:
        selected = m.group(1)
        conf = int(m.group(2))
    if selected is None:
        m2 = RE_PLUGIN_MATCH.search(log)
        if m2:
            selected = m2.group(1)
            conf = int(m2.group(2))
    ep = None
    m3 = RE_STRUCTURE_EP.search(log)
    if m3:
        ep = m3.group(1).lower()
    dump_family = None
    m4 = RE_DUMP_FAMILY.search(log)
    if m4:
        dump_family = m4.group(1)
    return {
        "selected_family": selected,
        "plugin_confidence": conf,
        "structure_ep": ep,
        "dump_family": dump_family,
    }


def run_r0b(case_id: str, out_dir: Path, out_pe: Path, oracle: Path | None) -> dict:
    if not ACC.is_file():
        return {"skipped": True, "reason": "mida-acceptance missing"}
    digest = sha256_file(out_pe)
    size = out_pe.stat().st_size
    report = out_dir / "r0b_candidate.json"
    cmd = [
        str(ACC),
        "check-static",
        str(out_pe),
        "--expected-sha256",
        digest,
        "--expected-size",
        str(size),
        "--role",
        "candidate",
        "--report",
        str(report),
    ]
    if oracle and oracle.is_file():
        cmd.extend(["--oracle", str(oracle)])
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    (out_dir / "r0b_candidate.stdout.txt").write_text(
        (p.stdout or "") + "\n---STDERR---\n" + (p.stderr or ""), encoding="utf-8"
    )
    verdict = None
    failures = []
    if report.is_file():
        data = json.loads(report.read_text(encoding="utf-8"))
        verdict = data.get("verdict")
        failures = [f.get("code") or f.get("gate_id") for f in (data.get("failures") or [])]
    (out_dir / "candidate.sha256").write_text(f"{digest}  {out_pe.name}\n", encoding="utf-8")
    meta = {
        "case_id": case_id,
        "sha256": digest,
        "size": size,
        "exit_code": p.returncode,
        "verdict": verdict,
        "failures": failures,
        "report": str(report),
    }
    (out_dir / "r0b_candidate_meta.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )
    return meta


def main() -> int:
    known = known_case_ids()
    ap = argparse.ArgumentParser(
        description="Vault case live unpack (profile is explicit; never auto-selected for GTO)."
    )
    ap.add_argument("case_id", help=f"known: {', '.join(known)}")
    ap.add_argument("--pure-rebuild", action="store_true")
    ap.add_argument("--no-r0b", action="store_true")
    ap.add_argument("--tag", default="", help="optional tag appended to run dir name")
    ap.add_argument(
        "--profile",
        default="",
        help=(
            "mida-cli dump profile (explicit). "
            f"Known: {', '.join(sorted(KNOWN_PROFILES))}. "
            "Empty = CLI default (oreans-classic). "
            "GTO heap/container stages require ahk-gto-experimental."
        ),
    )
    ap.add_argument(
        "--extra-cli-arg",
        action="append",
        default=[],
        dest="extra_cli_args",
        help="extra mida-cli arg (repeatable); use sparingly",
    )
    args = ap.parse_args()

    profile = (args.profile or "").strip()
    if profile and profile not in KNOWN_PROFILES:
        print(
            f"warning: profile {profile!r} not in known set {sorted(KNOWN_PROFILES)}; "
            "passing through to mida-cli",
            file=sys.stderr,
        )

    cfg = resolve_cfg(args.case_id)
    if cfg is None:
        print(
            f"unknown or unmaterialized case {args.case_id!r}; "
            f"known manifests/builtins: {known}",
            file=sys.stderr,
        )
        return 2

    src = cfg["src_path"]
    if not src.is_file():
        print("missing src", src, file=sys.stderr)
        return 2
    if not CLI.is_file():
        print("missing cli", CLI, file=sys.stderr)
        return 2

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.tag:
        run_id = f"{run_id}_{args.tag}"
    if args.pure_rebuild:
        run_id = f"{run_id}_pure"
    if profile == "ahk-gto-experimental":
        # Stable evidence marker when GTO experimental stages are on.
        if "gto" not in run_id.lower() and "p1exp" not in run_id.lower():
            run_id = f"{run_id}_gtoexp"
    out_dir = EV_ROOT / args.case_id / f"live_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    prefix = cfg["prefix"]
    work_input = out_dir / f"{prefix}_protected.exe"
    work_input.write_bytes(src.read_bytes())
    out_pe = out_dir / f"{prefix}_unpacked.exe"
    log_path = out_dir / "unpack.stdout.txt"
    meta_path = out_dir / "run_meta.json"

    cmd = [
        str(CLI),
        "/unpack",
        str(work_input),
        "-o",
        str(out_pe),
        "--data-sections",
        "--no-shrink",
        "-v",
    ]
    if profile:
        cmd.append(f"--profile={profile}")
    if args.pure_rebuild:
        cmd.append("--pure-rebuild")
    for extra in args.extra_cli_args or []:
        if extra:
            cmd.append(extra)

    meta = {
        "run_id": run_id,
        "case_id": args.case_id,
        "cmd": cmd,
        "started": datetime.now().isoformat(timespec="seconds"),
        "cli_mtime": CLI.stat().st_mtime,
        "src_sha_note": cfg["src_note"],
        "pure_rebuild": args.pure_rebuild,
        "profile": profile or None,
        "corpus_role": cfg.get("corpus_role"),
        "protection_family": cfg.get("protection_family"),
        "engine_route": cfg.get("engine_route"),
    }
    print("RUN", " ".join(cmd), flush=True)
    t0 = time.time()
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(CLI.parent),
    )
    elapsed = time.time() - t0
    log = (p.stdout or "") + "\n---STDERR---\n" + (p.stderr or "")
    log_path.write_text(log, encoding="utf-8")
    signals = parse_unpack_signals(log)
    meta.update(
        {
            "finished": datetime.now().isoformat(timespec="seconds"),
            "elapsed_sec": round(elapsed, 2),
            "exit_code": p.returncode,
            "out_pe_exists": out_pe.is_file(),
            "out_pe_size": out_pe.stat().st_size if out_pe.is_file() else None,
            "log": str(log_path),
            "signals": signals,
        }
    )
    print(
        "exit",
        p.returncode,
        "elapsed",
        round(elapsed, 2),
        "out",
        meta["out_pe_size"],
        "family",
        signals.get("selected_family"),
        "ep",
        signals.get("structure_ep"),
        flush=True,
    )
    for line in log.splitlines()[-30:]:
        print(line)

    r0b = None
    if p.returncode == 0 and out_pe.is_file() and not args.no_r0b:
        oracle = cfg.get("oracle_path")
        r0b = run_r0b(args.case_id, out_dir, out_pe, oracle)
        print(
            "R0B",
            r0b.get("verdict"),
            "exit",
            r0b.get("exit_code"),
            r0b.get("failures"),
            flush=True,
        )
        meta["r0b"] = r0b

    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    notes = out_dir / "notes.md"
    notes.write_text(
        f"# {args.case_id} live_{run_id}\n\n"
        f"- exit: {p.returncode}\n"
        f"- elapsed_sec: {meta['elapsed_sec']}\n"
        f"- out_size: {meta['out_pe_size']}\n"
        f"- pure_rebuild: {args.pure_rebuild}\n"
        f"- profile: {profile or '(default oreans-classic)'}\n"
        f"- selected_family: {signals.get('selected_family')}\n"
        f"- structure_ep: {signals.get('structure_ep')}\n"
        f"- r0b: {json.dumps(r0b, ensure_ascii=False) if r0b else 'n/a'}\n",
        encoding="utf-8",
    )
    return 0 if p.returncode == 0 else p.returncode


if __name__ == "__main__":
    sys.exit(main())
