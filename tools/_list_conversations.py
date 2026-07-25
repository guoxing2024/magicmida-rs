#!/usr/bin/env python3
"""List local OpenHands conversation history (user messages + finishes)."""
import json
import os
from datetime import datetime
from pathlib import Path


def extract_texts(obj):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("content", "message", "text", "prompt") and isinstance(v, str) and v.strip():
                out.append((k, v))
            else:
                out.extend(extract_texts(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(extract_texts(v))
    return out


def main():
    base = Path(os.environ["USERPROFILE"]) / ".openhands" / "conversations"
    if not base.exists():
        print("No conversations dir:", base)
        return

    convs = sorted(
        [p for p in base.iterdir() if p.is_dir()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    print(f"Found {len(convs)} conversation(s) under {base}\n")

    for conv in convs:
        mtime = datetime.fromtimestamp(conv.stat().st_mtime)
        print("=" * 70)
        print(f"ID: {conv.name}")
        print(f"LastWrite: {mtime.isoformat(sep=' ', timespec='seconds')}")

        bs = conv / "base_state.json"
        if bs.exists():
            try:
                d = json.loads(bs.read_text(encoding="utf-8"))
                print(f"Status: {d.get('execution_status', '?')}")
                print(f"Invoked skills: {d.get('invoked_skills', [])}")
                ws = d.get("workspace") or {}
                print(f"Workspace: {ws.get('working_dir') or ws}")
            except Exception as e:
                print(f"base_state parse error: {e}")

        events_dir = conv / "events"
        if not events_dir.exists():
            print("No events/")
            continue

        files = sorted(events_dir.glob("event-*.json"))
        print(f"Events: {len(files)}")

        for f in files:
            try:
                raw = f.read_text(encoding="utf-8")
                ev = json.loads(raw)
            except Exception:
                continue

            compact = raw.replace(" ", "")
            is_user = '"source":"user"' in compact or '"role":"user"' in compact
            is_finish = "FinishEvent" in raw or "FinishAction" in raw or (
                isinstance(ev.get("action"), dict) and "finish" in str(ev.get("action")).lower()
            )

            if not (is_user or is_finish):
                continue

            texts = extract_texts(ev)
            shown = False
            for k, v in texts:
                if k not in ("content", "message", "text"):
                    continue
                if len(v) > 800:
                    v = v[:800] + "..."
                label = "USER" if is_user else "FINISH"
                print(f"  [{label}] {f.name}:")
                for line in v.splitlines()[:12]:
                    print(f"    {line}")
                if v.count("\n") >= 12:
                    print("    ...")
                shown = True
                break
            if not shown and is_user:
                # content as list of parts
                content = ev.get("content") or (ev.get("action") or {}).get("content")
                if isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and part.get("text"):
                            t = part["text"]
                            if len(t) > 800:
                                t = t[:800] + "..."
                            print(f"  [USER] {f.name}:")
                            for line in t.splitlines()[:12]:
                                print(f"    {line}")
                            break


if __name__ == "__main__":
    main()
