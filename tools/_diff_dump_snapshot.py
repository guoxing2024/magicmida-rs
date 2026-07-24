# -*- coding: utf-8 -*-
"""Diff two mida.dump-snapshot-manifest/v0 sidecars (or synthesize from .boot).

Usage:
  python tools/_diff_dump_snapshot.py a.dump_snapshot.json b.dump_snapshot.json
  python tools/_diff_dump_snapshot.py --boot-legacy path_a.exe path_b.exe

Does not write validation_summary or claim R0B Accepted.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_manifest(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not str(data.get("schema_version", "")).startswith("mida.dump-snapshot"):
        print(f"warn: unexpected schema {data.get('schema_version')!r}", file=sys.stderr)
    return data


def summarize(label: str, m: dict) -> None:
    s = m.get("summary") or {}
    print(f"=== {label} ===")
    print(f"  profile={m.get('profile')} entry={m.get('entry_point_rva')}")
    print(
        f"  containers={s.get('container_count')} heap_globals={s.get('heap_global_count')} "
        f"roots={s.get('image_roots')} kids={s.get('graph_children')} handles={s.get('heap_handles')}"
    )
    print(
        f"  payload container={s.get('container_payload_bytes')} "
        f"heap={s.get('heap_global_payload_bytes')} total={s.get('total_capture_payload_bytes')}"
    )


def index_by_rva(entries: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for e in entries:
        rva = str(e.get("rva") or "0x0")
        # Multiple graph children share rva 0 — keep list under special key.
        if rva in ("0x0", "0", "0x00"):
            out.setdefault("__graph__", {"_multi": []})
            out["__graph__"]["_multi"].append(e)
            continue
        # First image-root wins for map compare (duplicates rare).
        out.setdefault(rva, e)
    return out


def diff_manifests(a: dict, b: dict, label_a: str, label_b: str) -> int:
    summarize(label_a, a)
    summarize(label_b, b)
    sa = a.get("summary") or {}
    sb = b.get("summary") or {}
    print()
    print("=== summary delta (b - a) ===")
    for k in (
        "container_count",
        "heap_global_count",
        "image_roots",
        "graph_children",
        "container_payload_bytes",
        "heap_global_payload_bytes",
        "total_capture_payload_bytes",
    ):
        va, vb = sa.get(k), sb.get(k)
        if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
            print(f"  {k}: {va} -> {vb} (delta={vb - va:+})")
        else:
            print(f"  {k}: {va} -> {vb}")

    ha = {e.get("rva"): e for e in (a.get("heap_globals") or []) if e.get("rva") not in (None, "0x0", "0")}
    hb = {e.get("rva"): e for e in (b.get("heap_globals") or []) if e.get("rva") not in (None, "0x0", "0")}
    only_a = sorted(set(ha) - set(hb))
    only_b = sorted(set(hb) - set(ha))
    common = sorted(set(ha) & set(hb))
    print()
    print(f"image-root rva only in a: {len(only_a)} only in b: {len(only_b)} common: {len(common)}")
    size_diffs = []
    for rva in common:
        sa_ = int(ha[rva].get("content_size") or 0)
        sb_ = int(hb[rva].get("content_size") or 0)
        if sa_ != sb_:
            size_diffs.append((rva, sa_, sb_, sb_ - sa_))
    size_diffs.sort(key=lambda t: -abs(t[3]))
    print(f"same-rva size diffs: {len(size_diffs)}")
    for rva, sa_, sb_, d in size_diffs[:20]:
        print(f"  {rva}: {sa_} -> {sb_} (delta={d:+})")

    ga = sum(
        int(e.get("content_size") or 0)
        for e in (a.get("heap_globals") or [])
        if e.get("rva") in (None, "0x0", "0") or e.get("is_graph_child")
    )
    # Prefer is_graph_child when present
    def kids_bytes(m: dict) -> int:
        total = 0
        for e in m.get("heap_globals") or []:
            if e.get("is_graph_child") is True or e.get("rva") in ("0x0", "0", "0x00"):
                total += int(e.get("content_size") or 0)
        return total

    print(f"graph_child payload: a={kids_bytes(a)} b={kids_bytes(b)} delta={kids_bytes(b)-kids_bytes(a):+}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Diff dump snapshot manifests")
    ap.add_argument("a", type=Path, help="First .dump_snapshot.json")
    ap.add_argument("b", type=Path, help="Second .dump_snapshot.json")
    args = ap.parse_args()
    if not args.a.is_file() or not args.b.is_file():
        print("need two existing manifest files", file=sys.stderr)
        return 2
    return diff_manifests(load_manifest(args.a), load_manifest(args.b), str(args.a), str(args.b))


if __name__ == "__main__":
    raise SystemExit(main())
