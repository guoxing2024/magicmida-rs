import subprocess, sys, os
r = subprocess.run(["cmd", "/c", "cargo --version"], cwd=r"D:\Claude project\magicmida-rs", capture_output=True)
sys.stdout.buffer.write(b"===STDOUT===\n" + r.stdout)
sys.stdout.buffer.write(b"\n===STDERR===\n" + r.stderr)
sys.stdout.buffer.write(f"\nRC={r.returncode}\n".encode())