import subprocess, sys, os
vcvars = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cmdline = f'call "{vcvars}" >nul 2>&1 && cargo check -p mida-cli --offline'
r = subprocess.run(["cmd", "/c", cmdline], cwd=r"D:\Claude project\magicmida-rs", capture_output=True)
sys.stdout.buffer.write(b"===STDOUT===\n" + r.stdout[-6000:])
sys.stdout.buffer.write(b"\n===STDERR===\n" + r.stderr[-6000:])
sys.stdout.buffer.write(f"\nRC={r.returncode}\n".encode())