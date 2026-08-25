import subprocess, sys, os
vcvars = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
r = subprocess.run(f'cmd /c call "{vcvars}" >nul 2>&1 && set', shell=True, capture_output=True, text=True)
for line in r.stdout.splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        os.environ[k] = v
r2 = subprocess.run(["cargo", "test", "-p", "mida-cli", "--lib", "walker_dispatch", "--", "--test-threads=1"], cwd=r"D:\Claude project\magicmida-rs", capture_output=True, text=True, env=os.environ)
print("RC=", r2.returncode)
print("OUT_TAIL:", r2.stdout[-6000:])
print("ERR_TAIL:", r2.stderr[-3000:])