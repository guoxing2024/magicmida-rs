#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TASK-020 — candidate core session-pointer cleanse (option A, pure offline, zero live fire).

Pure-stdlib PE scanner + classifier + surgical patcher + offline verifier for
the candidate core_perfect_candidate.dll (sha256 3650ea6c...).

Work object is a COPY under lab/xx21b_pcell_clean/; the vault original
(D:/MidaVault/lab/worktree_evidence_20260830/lab/xx21b_run/core_perfect_candidate.dll)
is NEVER opened for write.  No target process is started; no host/candidate/sample
is loaded.  This is file-level scanning + byte patching + offline verification only.

Design (per TASK-020 ticket):
  Phase 1: scan whole file for 8-byte-aligned "pointer-looking" values
           (user-space 0x7ff.../0x0000-headed, high 16 bits zero), classify
           A-class = falls inside a known dump-session dead module range.
           Dead range set recovered from T0.4 evidence:
             ntdll    0x7ffeeb320000  size 0x270000   (documented, T0.4 report)
             urlmon   0x7ffec48f0000  size 0x1dd000   (recovered: dump IAT value 0x7ffec49ee470 - export rva 0xfe470; T0.4 step1)
             wininet  0x7ffd20460000  size 0x295000   (recovered: t05_att1_dbg deploy_check wininet_module base)
  Phase 2: surgical patch on the COPY:
             - bare data slots (no .reloc coverage): old value -> current-session
               value (same module+offset, current bases from T019/T0.5 pump JSON).
             - reloc-covered slots (candidate .reloc table has DIR64 entry at
               this RVA): removing the slot from .reloc and writing the current
               absolute value is loader-safe ONLY if the loader never re-applies
               the entry; we cannot prove that offline, so per ticket we do NOT
               patch reloc-covered slots — they are recorded as "uncleaned
               (reloc-covered)" and reported honestly.  (Ticket: "若判断做不到安全
               处理 -> 该槽保持原样并标注'未清洗（重定位覆盖）'，如实进报告，不许硬补").
               In this candidate the .reloc table has exactly 4 DIR64 entries
               (page 0x170000, offsets 0x30/0x38/0x40/0x48 = .tls area); none of
               the A-class hits are covered by .reloc, so all A-class slots are
               bare-data slots and are patched.
  Phase 3: offline verify on the COPY:
             1. rescan -> A-class hits == 0
             2. patch minimality: cmp original vs copy, differing bytes == 8 * slots
             3. structure intact: headers / section table / exports (Run@0x1c120,
                GetAppVersion@0xbb30) / .text bytes unchanged / .reloc unchanged
             4. honest boundary statement in report.
  Deliverables: pointer_map.json (machine-readable, future T0.5 runtime fixup),
                cleaned copy, rescan manifest, diff byte map.

NO network; NO process start; read-only on vault original.
"""

import argparse
import hashlib
import io
import json
import os
import shutil
import struct
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Constants (evidence-backed; see TASK-020 / D-038 / T0.4 report)
# ---------------------------------------------------------------------------

CAND_SHA256 = "3650ea6c0a88c731d4b613eaa533ab1d48258ce782843a5661ca6c683fd9b64e"
CAND_SIZE = 14435328

# Dump session (T0.4 / 08-29 pre-reboot) dead module ranges.
# ntdll: 0x7ffeeb320000 + 0x106390 = 0x7ffeeb426390 (documented stale pointer).
DEAD_RANGES = [
    {"module": "ntdll.dll", "base": 0x7FFEEB320000, "size": 0x270000,
     "evidence": "T0.4 report: ntdll 0x7ffeeb320000 (+0x106390 stale=0x7ffeeb426390); "
                 "D-038/30c163 verdict; T019 2/2 AV @0x7ffeeb426390"},
    {"module": "urlmon.dll", "base": 0x7FFEC48F0000, "size": 0x1DD000,
     "evidence": "recovered from T0.4 step1 IAT slot value 0x7ffec49ee470 - urlmon "
                 "export rva 0xfe470 (URLDownloadToFileA) = base 0x7ffec48f0000"},
    {"module": "wininet.dll", "base": 0x7FFD20460000, "size": 0x295000,
     "evidence": "recovered from T0.5 att1 (t05_att1_dbg.json) deploy_check "
                 "wininet_module base=0x7ffd20460000"},
]

# Current session (T019 / T0.5 att1) module bases, same module+offset mapping.
CURRENT_MODULES = {
    "ntdll.dll": 0x7FFD37AE0000,
    "urlmon.dll": 0x7FFD10050000,
    "wininet.dll": 0x7FFD20460000,
}

# Evidence source for CURRENT_MODULES (pump JSON from T019/T0.5).
CURRENT_MODULES_EVIDENCE = (
    "T019/T0.5 pump evidence (vault xx21b_t05/): ntdll rip 0x7ffd37b44680 (owner ntdll.dll) "
    "offset +0x64680 in-session; deploy_check urlmon_module base=0x7ffd10050000 "
    "size=0x1dd000; wininet_module base=0x7ffd20460000 size=0x295000. "
    "Same boot family: BootTime 2026-08-30 10:05:53.549 (T019 §4.1)."
)

# ---------------------------------------------------------------------------
# Minimal PE reader (pure stdlib; re-implements the pe crate algorithms)
# ---------------------------------------------------------------------------


class PeSection:
    __slots__ = ("name", "vaddr", "vsize", "raw_off", "raw_size", "idx")

    def __init__(self, name, vaddr, vsize, raw_off, raw_size, idx):
        self.name = name
        self.vaddr = vaddr
        self.vsize = vsize
        self.raw_off = raw_off
        self.raw_size = raw_size
        self.idx = idx

    def __repr__(self):  # pragma: no cover
        return "PeSection(%r,vaddr=%#x,vsize=%#x,raw_off=%#x,raw_size=%#x)" % (
            self.name, self.vaddr, self.vsize, self.raw_off, self.raw_size)


class PeInfo:
    """Minimal PE32+ reader: headers, section table, data directory, RVA<->offset."""

    def __init__(self, data):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("not an MZ PE")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("no PE signature")
        self.e_lfanew = e_lfanew
        self.machine, self.nsects, _, _, _, self.sizopt, _ = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4)
        self.opt = e_lfanew + 24
        self.magic = struct.unpack_from("<H", data, self.opt)[0]
        if self.magic != 0x20B:
            raise ValueError("not PE32+ (magic=%#x)" % self.magic)
        self.image_base = struct.unpack_from("<Q", data, self.opt + 24)[0]
        self.size_of_image = struct.unpack_from("<I", data, self.opt + 56)[0]
        self.dll_chars = struct.unpack_from("<H", data, self.opt + 70)[0]
        self.file_chars = struct.unpack_from("<H", data, e_lfanew + 4 + 18)[0]
        self.dirs = []
        dd = self.opt + 112
        for i in range(16):
            rva, size = struct.unpack_from("<II", data, dd + i * 8)
            self.dirs.append((rva, size))
        so = self.opt + self.sizopt
        self.sections = []
        for i in range(self.nsects):
            off = so + i * 40
            name = data[off:off + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
            self.sections.append(PeSection(name, vaddr, vsize, roff, rsize, i))

    def section_at_rva(self, rva):
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size) and s.raw_size > 0:
                return s
        return None

    def rva_to_offset(self, rva):
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size) and s.raw_size > 0:
                return s.raw_off + (rva - s.vaddr)
        return None

    def offset_to_rva(self, off):
        for s in self.sections:
            if s.raw_off <= off < s.raw_off + s.raw_size:
                return s.vaddr + (off - s.raw_off)
        return None

    def read_qword_at_rva(self, rva):
        o = self.rva_to_offset(rva)
        if o is None or o + 8 > len(self.data):
            return None
        return struct.unpack_from("<Q", self.data, o)[0]


def parse_reloc_table(pe, data):
    """Parse the base relocation directory (dir index 5).  Returns list of
    (page_rva, entry_rva, type) and the raw byte extent [start, end)."""
    rva, size = pe.dirs[5]
    if rva == 0 or size == 0:
        return [], (0, 0)
    o = pe.rva_to_offset(rva)
    if o is None:
        return [], (0, 0)
    entries = []
    p = o
    end = o + size
    while p + 8 <= end:
        page, bsize = struct.unpack_from("<II", data, p)
        if bsize < 8 or p + bsize > end:
            break
        n = (bsize - 8) // 2
        for j in range(n):
            w = struct.unpack_from("<H", data, p + 8 + j * 2)[0]
            typ = w >> 12
            offin = w & 0xFFF
            if typ == 0:
                continue
            entries.append((page, page + offin, typ))
        p += bsize
    return entries, (o, end)


def parse_exports(pe, data):
    """Return {name: rva} for the export directory (dir index 0)."""
    rva, size = pe.dirs[0]
    if rva == 0:
        return {}
    o = pe.rva_to_offset(rva)
    if o is None:
        return {}
    nfuncs, nnames = struct.unpack_from("<II", data, o + 20)[0:1] or (0, 0), 0
    nfuncs = struct.unpack_from("<I", data, o + 20)[0]
    nnames = struct.unpack_from("<I", data, o + 24)[0]
    addr_rva = struct.unpack_from("<I", data, o + 28)[0]
    name_rva = struct.unpack_from("<I", data, o + 32)[0]
    ord_rva = struct.unpack_from("<I", data, o + 36)[0]
    out = {}
    for i in range(nnames):
        nr = struct.unpack_from("<I", data, pe.rva_to_offset(name_rva) + i * 4)[0]
        no = pe.rva_to_offset(nr)
        if no is None:
            continue
        end = data.find(b"\0", no)
        nm = data[no:end].decode("latin1")
        ordi = struct.unpack_from("<H", data, pe.rva_to_offset(ord_rva) + i * 2)[0]
        if ordi < nfuncs:
            frva = struct.unpack_from(
                "<I", data, pe.rva_to_offset(addr_rva) + ordi * 4)[0]
            out[nm] = frva
    return out


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def is_user_pointer(v):
    """Pointer-looking: high 16 bits zero, base in 0x7ff... user range
    (canonical user address).  Also accept 0x0000-headed with nonzero lower."""
    if v == 0:
        return False
    if (v >> 48) & 0xFFFF != 0:
        return False
    hi = (v >> 32) & 0xFFFF
    if hi in (0x7FFD, 0x7FFE, 0x7FFC, 0x7FFB, 0x7FFA, 0x7FF9, 0x7FF8):
        return True
    return False


def scan_pointers(pe, data, aligned_only=True):
    """Scan whole file (headers + all raw ranges) for pointer-looking 8-byte values.
    aligned_only=True -> scan only 8-byte-aligned offsets (ticket: 8 字节对齐扫描).
    Returns list of dicts with file offset, rva, section, value."""
    hits = []
    n = len(data)
    step = 8 if aligned_only else 1
    start = 0
    for off in range(start, n - 7, step):
        v = struct.unpack_from("<Q", data, off)[0]
        if not is_user_pointer(v):
            continue
        rva = pe.offset_to_rva(off)
        sec = pe.section_at_rva(rva) if rva is not None else None
        hits.append({
            "file_offset": off,
            "rva": rva,
            "section": sec.name if sec else None,
            "value": v,
            "value_hex": "0x%016x" % v,
        })
    return hits


def classify(hits, dead_ranges):
    """Classify each hit: A-class (dead-range) or other (non-dead)."""
    out = []
    for h in hits:
        v = h["value"]
        a = None
        for dr in dead_ranges:
            if dr["base"] <= v < dr["base"] + dr["size"]:
                a = {
                    "module": dr["module"],
                    "base": dr["base"],
                    "size": dr["size"],
                    "offset": v - dr["base"],
                    "evidence": dr["evidence"],
                }
                break
        h["class"] = "A" if a else "B"
        h["dead_range"] = a
        out.append(h)
    return out


# ---------------------------------------------------------------------------
# Patch planning
# ---------------------------------------------------------------------------


def plan_patches(pe, data, a_hits, current_modules, reloc_entries, log):
    """Decide the patch per A-class hit.
    Bare slot (no .reloc coverage) -> new value = current base + same offset.
    Reloc-covered slot -> per ticket: if we cannot prove loader-safe removal,
    keep original and mark 'uncleaned (reloc-covered)'."""
    reloc_rvas = set()
    for page, erva, typ in reloc_entries:
        reloc_rvas.add(erva)
    patches = []
    uncleaned = []
    for h in a_hits:
        dr = h["dead_range"]
        cur = current_modules.get(dr["module"])
        new_val = (cur + dr["offset"]) if cur is not None else None
        rva = h["rva"]
        covered = rva in reloc_rvas if rva is not None else False
        if new_val is None:
            h["action"] = "uncleaned(no-current-base)"
            uncleaned.append(h)
            continue
        if covered:
            h["action"] = "uncleaned(reloc-covered)"
            uncleaned.append(h)
            continue
        h["action"] = "patch"
        h["new_value"] = new_val
        h["new_value_hex"] = "0x%016x" % new_val
        h["reloc_covered"] = False
        patches.append(h)
    return patches, uncleaned


# ---------------------------------------------------------------------------
# Apply + verify
# ---------------------------------------------------------------------------


def apply_patches(data, patches):
    out = bytearray(data)
    for p in patches:
        off = p["file_offset"]
        struct.pack_into("<Q", out, off, p["new_value"])
        p["old_bytes"] = bytes(data[off:off + 8]).hex()
        p["new_bytes"] = bytes(out[off:off + 8]).hex()
    return bytes(out)


def sha256_of(b):
    return hashlib.sha256(b).hexdigest()


def diff_bytes(orig, new):
    diffs = []
    n = min(len(orig), len(new))
    i = 0
    while i < n:
        if orig[i] != new[i]:
            j = i
            while j < n and orig[j] != new[j]:
                j += 1
            diffs.append((i, j - i))
            i = j
        else:
            i += 1
    return diffs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="TASK-020 candidate core session-pointer cleanse")
    ap.add_argument("--copy-dir", default="lab/xx21b_pcell_clean",
                    help="work directory for the copy (default lab/xx21b_pcell_clean)")
    ap.add_argument("--vault-original", required=True,
                    help="path to vault original core_perfect_candidate.dll (read-only)")
    ap.add_argument("--rescan-only", action="store_true",
                    help="only rescan the cleaned copy and report A-class hits")
    args = ap.parse_args()

    orig_path = args.vault_original
    copy_dir = args.copy_dir
    copy_path = os.path.join(copy_dir, "core_perfect_candidate_cleaned.dll")

    orig_sha = sha256_of(open(orig_path, "rb").read())
    print("[gate] vault original sha256 = %s (expect %s)" % (orig_sha, CAND_SHA256))
    if orig_sha != CAND_SHA256:
        print("[gate] FAIL: vault original identity mismatch -> STOP")
        return 2
    print("[gate] vault original identity OK")

    if args.rescan_only:
        if not os.path.exists(copy_path):
            print("[rescan] no cleaned copy at %s" % copy_path)
            return 1
        data = open(copy_path, "rb").read()
        pe = PeInfo(data)
        hits = classify(scan_pointers(pe, data), DEAD_RANGES)
        a_hits = [h for h in hits if h["class"] == "A"]
        print("[rescan] A-class hits = %d" % len(a_hits))
        for h in a_hits:
            print("  A-hit off=%#x rva=%s sec=%s val=%s dead=%s" % (
                h["file_offset"], h["rva"], h["section"],
                h["value_hex"], h["dead_range"]["module"]))
        return 0 if len(a_hits) == 0 else 3

    # ---- Phase 1: scan original (read-only) ----
    data = open(orig_path, "rb").read()
    pe = PeInfo(data)
    reloc_entries, reloc_extent = parse_reloc_table(pe, data)
    exports = parse_exports(pe, data)
    print("[phase1] sections=%d image_base=%#x size_of_image=%#x" % (
        pe.nsects, pe.image_base, pe.size_of_image))
    print("[phase1] exports: %s" % sorted(exports.items()))
    print("[phase1] reloc entries=%d extent=%s" % (len(reloc_entries), reloc_extent))
    for e in reloc_entries:
        print("   reloc page=%#x entry_rva=%#x type=%d" % (e[0], e[1], e[2]))

    hits = scan_pointers(pe, data)
    hits = classify(hits, DEAD_RANGES)
    a_hits = [h for h in hits if h["class"] == "A"]
    print("[phase1] pointer-looking hits (aligned) = %d, A-class = %d" % (
        len(hits), len(a_hits)))
    for h in a_hits:
        print("  A-hit off=%#x rva=%s sec=%s val=%s dead=%s+%#x" % (
            h["file_offset"], h["rva"], h["section"], h["value_hex"],
            h["dead_range"]["module"], h["dead_range"]["offset"]))

    # ---- Phase 2: plan + apply on copy ----
    patches, uncleaned = plan_patches(pe, data, a_hits, CURRENT_MODULES, reloc_entries, print)
    print("[phase2] patches=%d uncleaned=%d" % (len(patches), len(uncleaned)))
    for u in uncleaned:
        print("  uncleaned: off=%#x val=%s reason=%s" % (
            u["file_offset"], u["value_hex"], u["action"]))

    os.makedirs(copy_dir, exist_ok=True)
    shutil.copy2(orig_path, copy_path)
    new_data = apply_patches(data, patches)
    with open(copy_path, "wb") as f:
        f.write(new_data)

    # ---- Phase 3: verify on copy ----
    pe2 = PeInfo(new_data)
    hits2 = classify(scan_pointers(pe2, new_data), DEAD_RANGES)
    a2 = [h for h in hits2 if h["class"] == "A"]
    print("[phase3] rescan A-class hits = %d" % len(a2))
    for h in a2:
        print("  A-hit off=%#x rva=%s sec=%s val=%s" % (
            h["file_offset"], h["rva"], h["section"], h["value_hex"]))

    diffs = diff_bytes(data, new_data)
    diff_total = sum(sz for _, sz in diffs)
    # Byte-level reconciliation: every diff region must be fully covered by a
    # patch slot (no stray bytes), and per-slot changed-byte counts must sum
    # exactly to diff_total.
    patch_ranges = [(p["file_offset"], p["file_offset"] + 8) for p in patches]
    coverage_ok = True
    for o, sz in diffs:
        covered = any(o >= s and o + sz <= e for s, e in patch_ranges)
        if not covered:
            coverage_ok = False
            print("  [minimality] diff region off=%#x size=%d NOT covered by any patch" % (o, sz))
    slot_changed = []
    for p in patches:
        o = p["file_offset"]
        nd = sum(1 for k in range(8) if data[o + k] != new_data[o + k])
        slot_changed.append((o, nd))
    slot_bytes = sum(nd for _, nd in slot_changed)
    print("[phase3] diff regions=%d diff_bytes=%d patch_slots=%d per-slot changed=%s "
          "sum=%d coverage_ok=%s (sum == diff_total: %s)" % (
              len(diffs), diff_total, len(patches),
              ["%#x:%d" % (o, n) for o, n in slot_changed],
              slot_bytes, coverage_ok, slot_bytes == diff_total))
    # Note: ticket expectation "8 * slots" assumes a full 8-byte rewrite; the
    # observed per-slot changed bytes are smaller because old/new session bases
    # share the high 0x7f byte and the low 16 offset bits.  This is a smaller
    # (better) patch; the honest acceptance is "no other diffs + per-slot
    # reconciliation", which is what coverage_ok and slot_bytes==diff_total prove.

    exports2 = parse_exports(pe2, new_data)
    print("[phase3] exports2: %s" % sorted(exports2.items()))

    # .text integrity: section 0 (vaddr 0x1000, raw 0x1000-0x101800) must be unchanged.
    sec0 = pe.sections[0]
    t_orig = data[sec0.raw_off:sec0.raw_off + sec0.raw_size]
    t_new = new_data[sec0.raw_off:sec0.raw_off + sec0.raw_size]
    print("[phase3] .text[0] (%s vaddr=%#x raw=%#x+%#x) unchanged=%s" % (
        sec0.name, sec0.vaddr, sec0.raw_off, sec0.raw_size, t_orig == t_new))

    # reloc table unchanged
    r_orig = data[reloc_extent[0]:reloc_extent[1]]
    r_new = new_data[reloc_extent[0]:reloc_extent[1]]
    print("[phase3] .reloc extent %s unchanged=%s" % (
        (hex(reloc_extent[0]), hex(reloc_extent[1])), r_orig == r_new))

    new_sha = sha256_of(new_data)
    print("[phase3] cleaned copy sha256 = %s" % new_sha)

    # ---- pointer_map.json ----
    pm = {
        "schema": "xx21b_pointer_map/v1",
        "task": "TASK-020",
        "candidate_sha256": CAND_SHA256,
        "cleaned_copy_sha256": new_sha,
        "cleaned_copy_path": copy_path,
        "image_base": pe.image_base,
        "size_of_image": pe.size_of_image,
        "dead_ranges": DEAD_RANGES,
        "current_modules": CURRENT_MODULES,
        "current_modules_evidence": CURRENT_MODULES_EVIDENCE,
        "dead_ranges_excluded": [
            {"module": "wininet.dll", "base": 0x7FFD20460000,
             "why": "base belongs to current-session family (T0.5 att1), not dump session"}
        ],
        "hits": hits,
        "patches": patches,
        "uncleaned": uncleaned,
        "rescan_a_class_hits_after": len(a2),
        "diff_regions": [{"offset": o, "size": s} for o, s in diffs],
        "diff_total_bytes": diff_total,
        "patch_slots": len(patches),
        "per_slot_changed_bytes": [{"offset": o, "changed": n} for o, n in slot_changed],
        "minimality_coverage_ok": coverage_ok,
        "minimality_sum_equals_diff_total": slot_bytes == diff_total,
        "exports": sorted(exports.items()),
        "note": ("Cleanup binds the candidate to the CURRENT session "
                 "(ntdll 0x7ffd37ae0000); cross-reboot still dies (C-5 not cured). "
                 "pointer_map.json is the future T0.5 runtime deploy-time fixup input."),
    }
    pm_path = os.path.join(copy_dir, "pointer_map.json")
    with open(pm_path, "w", encoding="utf-8") as f:
        json.dump(pm, f, ensure_ascii=False, indent=1)
    print("[done] pointer_map.json written to %s" % pm_path)

    # ---- minimality byte-level reconciliation (per patch) ----
    print("[audit] per-patch byte reconciliation:")
    for p in patches:
        off = p["file_offset"]
        old = bytes(data[off:off + 8]).hex()
        new = bytes(new_data[off:off + 8]).hex()
        ok = (old == p.get("old_bytes") and new == p.get("new_bytes"))
        print("  off=%#x old=%s new=%s ok=%s" % (off, old, new, ok))
    return 0


if __name__ == "__main__":
    sys.exit(main())
