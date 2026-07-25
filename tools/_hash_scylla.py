import hashlib
from pathlib import Path

files = [
    Path(r"D:\magicmida-rs-build\InjectorCLIx64.exe"),
    Path(r"D:\magicmida-rs-build\HookLibraryx64.dll"),
]
for p in files:
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    print(f"{p.name} {p.stat().st_size} {h}")
