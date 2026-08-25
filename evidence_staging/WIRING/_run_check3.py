import subprocess, sys, os
vcvars = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
r = subprocess.run(f'cmd /c call "{vcvars}" >nul 2>&1 && set', shell=True, capture_output=True, text=True)
print("SET_RC=", r.returncode, "out_len=", len(r.stdout), "err_len=", len(r.stderr))
if r.returncode != 0:
    print("STDERR:", r.stderr[:1000])
else:
    for line in r.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            os.environ[k] = v
    print("link:", subprocess.run(["where", "link.exe"], capture_output=True, text=True).stdout.splitlines()[:3])
    r2 = subprocess.run(["cargo", "check", "-p", "mida-cli", "--offline"], cwd=r"D:\Claude project\magicmida-rs", capture_output=True, text=True, env=os.environ)
    print("CARGO_RC=", r2.returncode)
    print("OUT_TAIL:", r2.stdout[-5000:])
    print("ERR_TAIL:", r2.stderr[-5000:])