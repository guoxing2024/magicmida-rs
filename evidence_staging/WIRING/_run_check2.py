import subprocess, sys, os
vcvars = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
# dump env via cmd then import into python env
r = subprocess.run(["cmd", "/c", f'call "{vcvars}" >nul 2>&1 && set'], capture_output=True, text=True)
print("SET_RC=", r.returncode, "len=", len(r.stdout))
if r.returncode != 0:
    print("STDERR:", r.stderr[:2000])
else:
    # apply env
    for line in r.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            os.environ[k] = v
    print("link.exe:", subprocess.run(["where", "link.exe"], capture_output=True, text=True).stdout[:500])
    r2 = subprocess.run(["cargo", "check", "-p", "mida-cli", "--offline"], cwd=r"D:\Claude project\magicmida-rs", capture_output=True, text=True, env=os.environ)
    print("CARGO_RC=", r2.returncode)
    print("STDOUT_TAIL:", r2.stdout[-4000:])
    print("STDERR_TAIL:", r2.stderr[-4000:])