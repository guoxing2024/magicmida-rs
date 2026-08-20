
# -*- coding: utf-8 -*-
"""GTO-H1 static snapshot analyzer (offline, read-only).
Reads mida.dump-snapshot-manifest/v0 sidecars and emits:
  - region inventory (per heap_global/container: rva, live_ptr, size, flags, kind)
  - allocation timeline proxy (sorted by live_ptr; handle vs child vs root)
  - pointer graph edges (parent -> child via live_ptr containment)
  - base-relative candidates (live_ptr within image base range or near heap base)
Writes JSON artifacts into the evidence dir. No sample bytes are read.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from collections import Counter, defaultdict

IMAGE_BASE = 0x140000000

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def analyze(manifest_path: Path, label: str) -> dict:
    j = json.loads(manifest_path.read_text(encoding="utf-8"))
    out = {
        "label": label,
        "manifest_sha256": sha256_file(manifest_path),
        "schema": j.get("schema_version"),
        "profile": j.get("profile"),
        "image_base": j.get("image_base"),
        "entry_point_rva": j.get("entry_point_rva"),
    }
    containers = j.get("containers") or []
    heap_globals = j.get("heap_globals") or []

    def num(v):
        if v is None: return 0
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("0x") or v.startswith("0X"): return int(v, 16)
            return int(v, 10)
        return int(v)

    # ---- region inventory ----
    regions = []
    for c in containers:
        regions.append({
            "kind": "container",
            "rva": num(c.get("rva")), "content_size": num(c.get("content_size")),
            "capacity_size": num(c.get("capacity_size")), "payload_bytes": num(c.get("payload_bytes")),
            "live_begin": num(c.get("live_begin")), "cookie": c.get("cookie"),
        })
    for g in heap_globals:
        regions.append({
            "kind": "heap_global",
            "rva": num(g.get("rva")), "content_size": num(g.get("content_size")),
            "live_ptr": num(g.get("live_ptr")),
            "is_heap_handle": bool(g.get("is_heap_handle")),
            "is_image_inline": bool(g.get("is_image_inline")),
            "is_graph_child": bool(g.get("is_graph_child")),
        })
    out["region_count"] = len(regions)
    out["container_count"] = len(containers)
    out["heap_global_count"] = len(heap_globals)
    out["regions"] = regions

    # ---- classification ----
    kinds = Counter(r["kind"] for r in regions)
    out["kind_counts"] = dict(kinds)
    handles = [r for r in regions if r.get("is_heap_handle")]
    roots = [r for r in regions if r.get("kind") == "heap_global" and not r.get("is_graph_child") and not r.get("is_heap_handle")]
    children = [r for r in regions if r.get("kind") == "heap_global" and r.get("is_graph_child")]
    out["handle_count"] = len(handles)
    out["root_count"] = len(roots)
    out["child_count"] = len(children)

    # ---- live pointer range stats (allocation timeline proxy) ----
    ptrs = [r["live_ptr"] for r in regions if r.get("live_ptr")]
    if ptrs:
        out["live_ptr_min"] = hex(min(ptrs))
        out["live_ptr_max"] = hex(max(ptrs))
        out["live_ptr_span"] = hex(max(ptrs) - min(ptrs))
    # image-inline? (live_ptr within image range)
    img_lo = IMAGE_BASE
    img_hi = IMAGE_BASE + 0x1_000_000  # generous
    in_image = [r for r in regions if r.get("live_ptr") and img_lo <= r["live_ptr"] < img_hi]
    out["live_ptr_in_image_range"] = len(in_image)

    # ---- pointer graph (containment edges) ----
    edges = []
    for r in regions:
        if not r.get("live_ptr"): continue
        for s in regions:
            if s is r: continue
            if s.get("live_ptr") and r["live_ptr"] < s["live_ptr"] < r["live_ptr"] + max(r.get("content_size", 0), r.get("capacity_size", 0)):
                edges.append({"from": hex(r["live_ptr"]), "to": hex(s["live_ptr"]), "kind": r["kind"]})
    out["pointer_graph_edge_count"] = len(edges)
    out["pointer_graph_edges"] = edges[:200]

    # ---- base-relative candidate detection ----
    # live_ptrs that look like offsets from a base (small values or aligned to 0x1000)
    base_rel = []
    for r in regions:
        p = r.get("live_ptr")
        if p is None: continue
        if p < 0x100000 or (p % 0x1000 == 0 and p < 0x1000000):
            base_rel.append({"live_ptr": hex(p), "kind": r["kind"], "rva": hex(r.get("rva", 0))})
    out["base_relative_candidates"] = base_rel[:100]
    out["base_relative_candidate_count"] = len(base_rel)

    # ---- size histogram ----
    hist = Counter()
    for r in regions:
        s = r.get("content_size") or r.get("capacity_size") or 0
        if s <= 0x40: hist["<=0x40"] += 1
        elif s <= 0x100: hist["<=0x100"] += 1
        elif s <= 0x400: hist["<=0x400"] += 1
        elif s <= 0x1000: hist["<=0x1000"] += 1
        elif s <= 0x10000: hist["<=0x10000"] += 1
        else: hist[">0x10000"] += 1
    out["size_histogram"] = dict(hist)

    # ---- region hash/diff (per-region content is not stored; manifest-level diff via sha) ----
    return out

def main() -> int:
    base = Path(r"D:\MidaVault\lab\evidence\gto_launcher")
    runs = [
        ("r27", base / "r27_nobypass_round0_20260725" / "gto_unpacked.dump_snapshot.json"),
        ("scan60", base / "live_20260724-124524_u_gto_host_scan60" / "gto_unpacked.dump_snapshot.synthetic.json"),
        ("r4c", base / "live_20260723-225951_r4c_gto" / "gto_unpacked.dump_snapshot.synthetic.json"),
        ("r25b", base / "live_r25b_newclassname" / "gto_unpacked.dump_snapshot.json"),
    ]
    results = {}
    for label, p in runs:
        if not p.exists():
            print(f"[skip] {label}: {p} missing", file=sys.stderr)
            continue
        try:
            results[label] = analyze(p, label)
            print(f"[ok] {label}: regions={results[label]['region_count']} roots={results[label]['root_count']} children={results[label]['child_count']} handles={results[label]['handle_count']} ptr_span={results[label].get('live_ptr_span')}")
        except Exception as e:
            print(f"[fail] {label}: {e}", file=sys.stderr)
    # cross-run diff summary
    keys = list(results)
    diff = {}
    if len(keys) >= 2:
        a, b = keys[0], keys[1]
        ra = {r["live_ptr"]: r for r in results[a]["regions"] if r.get("live_ptr")}
        rb = {r["live_ptr"]: r for r in results[b]["regions"] if r.get("live_ptr")}
        diff = {
            "label_a": a, "label_b": b,
            "only_a": len(set(ra) - set(rb)),
            "only_b": len(set(rb) - set(ra)),
            "common": len(set(ra) & set(rb)),
        }
    out = {"schema_version": "mida.gto-h1-snapshot-analysis/v1", "runs": results, "cross_run": diff}
    dest = Path(r"D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H1_model")
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "snapshot_region_inventory.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[written] {dest / 'snapshot_region_inventory.json'}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
