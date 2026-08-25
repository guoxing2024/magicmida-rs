import subprocess, os
vcvars = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
r = subprocess.run(f'cmd /c call "{vcvars}" && set', shell=True, capture_output=True, text=True)
print("VCVARS_RC=", r.returncode, "err:", r.stderr[:800])
env = dict(os.environ)
if r.returncode == 0 and len(r.stdout) > 1000:
    for line in r.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
# ensure MSVC link first regardless
msvc_bin = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64"
kits = r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64"
if os.path.isdir(msvc_bin):
    path = env.get("PATH","")
    cleaned = ";".join(p for p in path.split(";") if "Git\\usr\\bin" not in p and "Git\\mingw64\\bin" not in p)
    env["PATH"] = msvc_bin + ";" + kits + ";" + cleaned
    print("link.exe ->", msvc_bin + "\\link.exe", os.path.isfile(msvc_bin + "\\link.exe"))
r2 = subprocess.run(["cargo", "test", "-p", "mida-cli", "--lib", "walker_dispatch", "--", "--test-threads=1"], cwd=r"D:\Claude project\magicmida-rs", capture_output=True, text=True, env=env)
print("RC=", r2.returncode)
print("OUT_TAIL:", r2.stdout[-7000:])
print("ERR_TAIL:", r2.stderr[-2500:])