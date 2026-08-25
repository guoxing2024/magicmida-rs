import subprocess, sys, os
for vcvars in [r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
               r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"]:
    print("=== trying:", vcvars)
    r = subprocess.run(["cmd", "/c", f'call "{vcvars}" && set'], capture_output=True, text=True)
    print("RC=", r.returncode, "out_len=", len(r.stdout), "err_len=", len(r.stderr))
    print("ERR_HEAD:", r.stderr[:500])
    if r.returncode == 0 and len(r.stdout) > 1000:
        print("GOOD vcvars:", vcvars)
        break