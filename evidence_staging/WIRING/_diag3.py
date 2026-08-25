import subprocess, sys, os
vcvars = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
r = subprocess.run(f'cmd /c call "{vcvars}" >nul 2>&1 && set', shell=True, capture_output=True, text=True)
for line in r.stdout.splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        os.environ[k] = v
print("PATH:", os.environ.get("PATH", "")[:3000])
print("---link candidates---")
for p in os.environ.get("PATH","").split(";"):
    import os.path
    cand = os.path.join(p, "link.exe")
    if os.path.isfile(cand):
        print(cand)