
# -*- coding: utf-8 -*-
"""GTO-H1 cold-start failure timeline extractor (offline, read-only). v2"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

STAGE_ORDER = [
    "feature_gate", "capture_policy_parse", "create_process_attach",
    "observe_gto", "process_exit_before_dump", "container_detection",
    "heap_global_detection", "raw_slab_capture", "raw_slab_overlay",
    "synthetic_regions", "rebuild", "output", "acceptance",
]

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LINE_RE = re.compile(r"^\[(\d{4}-\d{2}-\d{2}T[^]]+)\] \[(DEBUG|INFO|WARN|ERROR|FATAL|TRACE)\]\s?(.*)$")

def parse_stderr(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    events = []
    for raw_ln in lines:
        ln = ANSI_RE.sub("", raw_ln)
        m = LINE_RE.match(ln)
        if not m:
            continue
        ts, level, msg = m.group(1), m.group(2), m.group(3)
        events.append({"ts": ts, "level": level, "msg": msg})
    stage_hits = {}
    for ev in events:
        msg = ev["msg"].lower()
        for st in STAGE_ORDER:
            if st in msg:
                stage_hits.setdefault(st, []).append(ev["ts"])
    fatal = [e for e in events if e["level"] == "FATAL"]
    errors = [e for e in events if e["level"] == "ERROR"]
    warns = [e for e in events if e["level"] == "WARN"]
    first = events[0]["ts"] if events else None
    last = events[-1]["ts"] if events else None

    failure = None
    if fatal:
        m = re.search(r"GTO_UNPACK_FAILED stage=([a-z_]+) error=(.*)$", fatal[-1]["msg"])
        if m:
            failure = {"stage": m.group(1), "error": m.group(2)}
        else:
            failure = {"stage": "unknown", "error": fatal[-1]["msg"]}

    return {
        "source": str(path),
        "line_count": len(lines),
        "event_count": len(events),
        "first_event_ts": first,
        "last_event_ts": last,
        "level_counts": {lv: sum(1 for e in events if e["level"] == lv) for lv in ("DEBUG","INFO","WARN","ERROR","FATAL")},
        "stage_first_seen": {k: v[0] for k, v in stage_hits.items()},
        "stage_hit_counts": {k: len(v) for k, v in stage_hits.items()},
        "terminal_failure": failure,
        "error_events": errors[:10],
        "warn_events": warns[:10],
    }

def main() -> int:
    base = Path(r"D:\MidaVault\lab\evidence\gto_launcher")
    runs = {
        "route_o_r1": base / "live_20260809T154340Z_route_o_r1_end_to_end_recovery" / "child.stderr.txt",
        "route_x_r1": base / "live_20260810T180501Z_route_x_r1_ledger_closure" / "child.stderr.txt",
        "route_y1a6": base / "live_20260811T173546Z_route_y1_a6_declared_size_reinit" / "child.stderr.txt",
        "r27": base / "r27_nobypass_round0_20260725" / "unpack.stdout.txt",
    }
    out = {"schema_version": "mida.gto-h1-failure-timeline/v1"}
    for label, p in runs.items():
        if not p.exists():
            out[label] = {"status": "missing", "path": str(p)}
            print(f"[skip] {label}", file=sys.stderr)
            continue
        try:
            parsed = parse_stderr(p)
            out[label] = {
                "status": "ok",
                "event_count": parsed["event_count"],
                "first_ts": parsed["first_event_ts"],
                "last_ts": parsed["last_event_ts"],
                "levels": parsed["level_counts"],
                "stage_first_seen": parsed["stage_first_seen"],
                "stage_hit_counts": parsed["stage_hit_counts"],
                "terminal_failure": parsed["terminal_failure"],
            }
            print(f"[ok] {label}: events={parsed['event_count']} fatal={parsed['level_counts']['FATAL']} failure={parsed['terminal_failure']}")
        except Exception as e:
            out[label] = {"status": "error", "detail": str(e)}
            print(f"[fail] {label}: {e}", file=sys.stderr)
    dest = Path(r"D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H1_model")
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "cold_start_failure_timeline.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[written] {dest / 'cold_start_failure_timeline.json'}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
