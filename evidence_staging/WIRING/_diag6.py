import subprocess, os
vcvars = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
r = subprocess.run(f'cmd /c call "{vcvars}" && set', shell=True, capture_output=True)
env = {}
for line in r.stdout.decode("utf-8", errors="replace").splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        env[k] = v
print("LIB=", env.get("LIB", "<MISSING>")[:1500])
print("WindowsSdkDir=", env.get("WindowsSdkDir", "<MISSING>"))
print("VCToolsInstallDir=", env.get("VCToolsInstallDir", "<MISSING>"))
# find kernel32.lib on disk
import glob
for pat in [r"C:\Program Files (x86)\Windows Kits\10\Lib\*\um\x64\kernel32.lib", r"C:\Program Files (x86)\Windows Kits\10\Lib\*\ucrt\x64\ucrt.lib"]:
    print(pat, "->", glob.glob(pat)[:3])