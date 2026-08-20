# -*- coding: utf-8 -*-
"""GTO-COLD-START-HEAP-REBASE-1 H1: parse observation-only stderr into a
structured heap/container inventory. Read-only analysis; writes JSON only."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RE_SLOT = re.compile(
    r"Captured heap-global slot rva=(0x[0-9a-f]+) heap=(0x[0-9a-f]+) size=(\d+) xref=(\d+)( in_data=true)?"
)
RE_HANDLE = re.compile(
    r"Captured heap-handle slot .*? rva=(0x[0-9a-f]+) heap=(0x[0-9a-f]+) xref=(\d+)"
)
RE_CHILD = re.compile(
    r"Captured heap-graph child \(no image slot\) heap=(0x[0-9a-f]+) size=(\d+) round=(\d+) parent_pri=(\d+)"
)
RE_DANGLING = re.compile(
    r"Captured dangling heap edge \(pre-scrub\) heap=(0x[0-9a-f]+) size=(\d+) refs=(\d+)"
)
RE_STAGE = re.compile(
    r'gto_stage_(enter|exit|error) stage="([^"]+)" .*?item_count=(\d+) byte_count=(\d+)( error="(.*)")?'
)
RE_SUMMARY = re.compile(
    r"Detected heap-global slots requiring post-CRT restore count=(\d+) graph_children=(\d+) heap_handle_slots=(\d+) total_bytes=(\d+)"
)


def parse(path: Path) -> dict:
    out = {
        "slots": [],
        "handles": [],
        "children": [],
        "dangling": [],
        "stages": [],
        "summary": None,
        "oep": None,
        "first_text_exec": None,
        "iat_resolved": None,
    }
    ansi_re = re.compile("\x1b\\[[0-9;]*m")
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8")
    for raw_line in text.splitlines():
        line = ansi_re.sub("", raw_line)
        m = RE_SLOT.search(line)
        if m:
            out["slots"].append({
                "rva": int(m.group(1), 16), "heap": int(m.group(2), 16),
                "size": int(m.group(3)), "xref": int(m.group(4)),
                "in_data": bool(m.group(5)),
            })
            continue
        m = RE_HANDLE.search(line)
        if m:
            out["handles"].append({
                "rva": int(m.group(1), 16), "heap": int(m.group(2), 16),
                "xref": int(m.group(3)),
            })
            continue
        m = RE_CHILD.search(line)
        if m:
            out["children"].append({
                "heap": int(m.group(1), 16), "size": int(m.group(2)),
                "round": int(m.group(3)), "parent_pri": int(m.group(4)),
            })
            continue
        m = RE_DANGLING.search(line)
        if m:
            out["dangling"].append({
                "heap": int(m.group(1), 16), "size": int(m.group(2)),
                "refs": int(m.group(3)),
            })
            continue
        m = RE_STAGE.search(line)
        if m:
            out["stages"].append({
                "event": m.group(1), "stage": m.group(2),
                "item_count": int(m.group(3)), "byte_count": int(m.group(4)),
                "error": m.group(5) or None,
            })
            continue
        m = RE_SUMMARY.search(line)
        if m:
            out["summary"] = {
                "count": int(m.group(1)), "graph_children": int(m.group(2)),
                "heap_handle_slots": int(m.group(3)), "total_bytes": int(m.group(4)),
            }
            continue
        m = re.search(r"OEP captured from RIP: (0x[0-9a-f]+)", line)
        if m:
            out["oep"] = int(m.group(1), 16)
            continue
        m = re.search(r"first decrypted \.text execution captured at (0x[0-9a-f]+)", line)
        if m:
            out["first_text_exec"] = int(m.group(1), 16)
            continue
        m = re.search(r"IAT resolved, first slot = (0x[0-9a-f]+)", line)
        if m:
            out["iat_resolved"] = int(m.group(1), 16)
    return out


def size_histogram(children: list[dict]) -> dict[str, int]:
    h: dict[str, int] = {}
    for c in children:
        s = c["size"]
        if s <= 0x40: k = "<=0x40"
        elif s <= 0x100: k = "<=0x100"
        elif s <= 0x400: k = "<=0x400"
        elif s <= 0x1000: k = "<=0x1000"
        elif s <= 0x2000: k = "<=0x2000"
        else: k = ">0x2000"
        h[k] = h.get(k, 0) + 1
    return dict(sorted(h.items()))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("stderr_paths", nargs="+")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    runs = {}
    for p in args.stderr_paths:
        run = parse(Path(p))
        runs[Path(p).parent.name] = run

    rva_sets = [set(r["rva"] for r in run["slots"]) for run in runs.values()]
    common_rvas = set.intersection(*rva_sets) if rva_sets else set()

    report = {
        "schema": "mida.gto-cold-start-h1-inventory/v1",
        "runs": {
            name: {
                "slot_count": len(r["slots"]),
                "handle_count": len(r["handles"]),
                "child_count": len(r["children"]),
                "dangling_count": len(r["dangling"]),
                "summary": r["summary"],
                "oep": r["oep"],
                "first_text_exec": r["first_text_exec"],
                "iat_resolved": r["iat_resolved"],
                "size_histogram": size_histogram(r["children"]),
                "stages": r["stages"],
            }
            for name, r in runs.items()
        },
        "cross_run": {
            "common_image_slot_rvas": sorted(common_rvas),
            "slot_count_stable": len(set(len(r["slots"]) for r in runs.values())) == 1,
            "child_count_values": sorted(set(len(r["children"]) for r in runs.values())),
            "all_slots": {
                name: [{"rva": s["rva"], "heap": s["heap"], "size": s["size"], "xref": s["xref"]} for s in r["slots"]]
                for name, r in runs.items()
            },
        },
    }
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
