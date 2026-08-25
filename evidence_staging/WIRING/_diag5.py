import subprocess, os
vcvars = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
r = subprocess.run(f'cmd /c call "{vcvars}" && set LIB', shell=True, capture_output=True)
print("RC=", r.returncode)
print("OUT:", r.stdout.decode("utf-8", errors="replace")[:2000])
print("ERR:", r.stderr.decode("utf-8", errors="replace")[:1000])