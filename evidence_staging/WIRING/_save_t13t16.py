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
r2 = subprocess.run(["cargo", "test", "-p", "mida-cli", "--lib", "walker_dispatch", "--", "--test-threads=1"], cwd=r"D:\Claude project\magicmida-rs", capture_output=True, env=env)
out = r2.stdout.decode("utf-8", errors="replace")
err = r2.stderr.decode("utf-8", errors="replace")
with open(r"D:\Claude project\magicmida-rs\evidence_staging\WIRING\walker_dispatch_test_raw.txt", "w", encoding="utf-8") as f:
    f.write("RC=" + str(r2.returncode) + "\n" + out + "\n---STDERR---\n" + err)
print("saved RC=", r2.returncode)