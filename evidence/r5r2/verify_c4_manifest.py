
#!/usr/bin/env python3
"""Independent verifier for IMP-09-CARRIER-R5-R2-CORRECTION-4 manifest.

Algorithm (byte-level, no JSON re-serialization):
  1. Read evidence/r5r2/imp09_carrier_r5_r2_c4_manifest.json as raw bytes.
  2. Remove the single line starting with exactly '  "self_sha256":'
     (the whole line INCLUDING its trailing LF newline).
  3. Join the remaining lines back with LF.
  4. SHA-256 the resulting bytes -> self_sha256.
  5. SHA-256 the raw file bytes -> raw_file_sha256 (compare to sidecar).
Exit code 0 = all MATCH; 1 = mismatch.
"""
import hashlib, io, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# ROOT = repo root (script at evidence/r5r2/verify_c4_manifest.py -> up 3)
p = os.path.join(ROOT, "evidence", "r5r2", "imp09_carrier_r5_r2_c4_manifest.json")
sp = os.path.join(ROOT, "evidence", "r5r2", "imp09_carrier_r5_r2_c4_manifest.sha256")

b = open(p, "rb").read()
if b"\r\n" in b:
    print("FATAL: manifest contains CRLF; expected LF-only")
    sys.exit(1)

lines = b.split(b"\n")
self_lines = [l for l in lines if l.startswith(b'  "self_sha256":')]
if len(self_lines) != 1:
    print("FATAL: expected exactly one self_sha256 line, found", len(self_lines))
    sys.exit(1)
removed = [l for l in lines if not l.startswith(b'  "self_sha256":')]
self_hash = hashlib.sha256(b"\n".join(removed)).hexdigest()
raw_hash = hashlib.sha256(b).hexdigest()
sidecar = io.open(sp, encoding="utf-8").read().split()[0]

d = json.loads(b.decode("utf-8"))
ok = True
if self_hash != d["self_sha256"]:
    print("SELF MISMATCH:", self_hash, "!=", d["self_sha256"])
    ok = False
else:
    print("SELF MATCH:", self_hash)
if raw_hash != sidecar:
    print("RAW MISMATCH:", raw_hash, "!=", sidecar)
    ok = False
else:
    print("RAW MATCH:", raw_hash)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
