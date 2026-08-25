import subprocess, os
MSVC = r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231"
KITS = r"C:\Program Files (x86)\Windows Kits\10"
SDK = "10.0.26100.0"
env = dict(os.environ)
path = env.get("PATH","")
cleaned = ";".join(p for p in path.split(";") if "Git\\usr\\bin" not in p and "Git\\mingw64\\bin" not in p)
env["PATH"] = MSVC + "\\bin\\Hostx64\\x64;" + KITS + "\\bin\\" + SDK + "\\x64;" + cleaned
env["LIB"] = MSVC + "\\lib\\x64;" + KITS + "\\Lib\\" + SDK + "\\um\\x64;" + KITS + "\\Lib\\" + SDK + "\\ucrt\\x64"
env["INCLUDE"] = MSVC + "\\include;" + KITS + "\\Include\\" + SDK + "\\ucrt;" + KITS + "\\Include\\" + SDK + "\\um;" + KITS + "\\Include\\" + SDK + "\\shared"
r2 = subprocess.run(["cargo", "test", "--workspace", "--", "--test-threads=1"], cwd=r"D:\Claude project\magicmida-rs", capture_output=True, env=env)
out = r2.stdout.decode("utf-8", errors="replace")
err = r2.stderr.decode("utf-8", errors="replace")
print("RC=", r2.returncode)
print("OUT_TAIL:", out[-9000:])
print("ERR_TAIL:", err[-3000:])