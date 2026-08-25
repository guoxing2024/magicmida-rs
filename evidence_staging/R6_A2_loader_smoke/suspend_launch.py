#!/usr/bin/env python3
"""GTO-R6-A2 loader smoke: launch target suspended (CREATE_SUSPENDED),
write PID to pidfile, then sleep holding the process object so cdb can attach
and set breakpoints before the Themida TLS chain executes.

Usage: python suspend_launch.py <target> <pidfile> [hold_seconds]
"""
import subprocess, sys, time, os

target = sys.argv[1]
pidfile = sys.argv[2]
hold = int(sys.argv[3]) if len(sys.argv) > 3 else 300

CREATE_SUSPENDED = 0x00000004
DETACHED = 0x00000008

p = subprocess.Popen(
    [target],
    creationflags=CREATE_SUSPENDED | DETACHED,
    close_fds=True,
)
with open(pidfile, "w") as f:
    f.write(str(p.pid))
print(f"PID={p.pid}", flush=True)
# Keep the Popen object (and thus the process handle) alive; cdb attaches and
# resumes the main thread. If the debugger never attaches, the process stays
# suspended and we release it after hold seconds to avoid orphans.
time.sleep(hold)
try:
    p.kill()
except Exception:
    pass
