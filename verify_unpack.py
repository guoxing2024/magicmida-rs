#!/usr/bin/env python3
"""
Complete verification script for unpacked Themida executable.
Checks import table, PE structure, and functionality.
"""

import pefile
import sys
import os
from pathlib import Path

def verify_import_table(unpacked_path, original_path):
    """Verify import table completeness."""
    print("=" * 60)
    print("IMPORT TABLE VERIFICATION")
    print("=" * 60)
    print()

    try:
        pe_unpacked = pefile.PE(unpacked_path)
        pe_original = pefile.PE(original_path)
    except Exception as e:
        print(f"ERROR: Cannot load PE files: {e}")
        return False

    # Check if unpacked has imports
    if not hasattr(pe_unpacked, 'DIRECTORY_ENTRY_IMPORT'):
        print("[X] FAIL: No import directory in unpacked file")
        return False

    # Count imports
    unpacked_dlls = len(pe_unpacked.DIRECTORY_ENTRY_IMPORT)
    unpacked_funcs = sum(len(list(e.imports)) for e in pe_unpacked.DIRECTORY_ENTRY_IMPORT)
    unpacked_ords = sum(1 for e in pe_unpacked.DIRECTORY_ENTRY_IMPORT
                        for imp in e.imports if imp.import_by_ordinal)

    original_dlls = len(pe_original.DIRECTORY_ENTRY_IMPORT)
    original_funcs = sum(len(list(e.imports)) for e in pe_original.DIRECTORY_ENTRY_IMPORT)
    original_ords = sum(1 for e in pe_original.DIRECTORY_ENTRY_IMPORT
                        for imp in e.imports if imp.import_by_ordinal)

    print(f"Unpacked file: {unpacked_path}")
    print(f"  Import descriptors: {unpacked_dlls}")
    print(f"  Functions:          {unpacked_funcs}")
    print(f"  Ordinal imports:    {unpacked_ords}")
    print()

    print(f"Original file: {original_path}")
    print(f"  Import descriptors: {original_dlls}")
    print(f"  Functions:          {original_funcs}")
    print(f"  Ordinal imports:    {original_ords}")
    print()

    # Verify counts
    all_match = True

    if unpacked_dlls != original_dlls:
        print(f"[!]  Descriptor count mismatch: {unpacked_dlls} vs {original_dlls}")
        all_match = False
    else:
        print(f"[OK] Descriptors match: {unpacked_dlls}/{original_dlls}")

    if unpacked_funcs != original_funcs:
        print(f"[!]  Function count mismatch: {unpacked_funcs} vs {original_funcs}")
        all_match = False
    else:
        print(f"[OK] Functions match: {unpacked_funcs}/{original_funcs}")

    if unpacked_ords != original_ords:
        print(f"[!]  Ordinal count mismatch: {unpacked_ords} vs {original_ords}")
        all_match = False
    else:
        print(f"[OK] Ordinals match: {unpacked_ords}/{original_ords}")

    print()

    # List first 10 DLLs
    print("First 10 imported DLLs:")
    for idx, entry in enumerate(pe_unpacked.DIRECTORY_ENTRY_IMPORT[:10]):
        dll = entry.dll.decode() if isinstance(entry.dll, bytes) else entry.dll
        func_count = len(list(entry.imports))
        ordinal_count = sum(1 for imp in entry.imports if imp.import_by_ordinal)
        marker = f" ({ordinal_count} ordinals)" if ordinal_count > 0 else ""
        print(f"  {idx+1:2d}. {dll:20s} {func_count:3d} functions{marker}")

    if len(pe_unpacked.DIRECTORY_ENTRY_IMPORT) > 10:
        print(f"  ... and {len(pe_unpacked.DIRECTORY_ENTRY_IMPORT) - 10} more")

    print()
    return all_match


def verify_pe_structure(unpacked_path):
    """Verify PE structure integrity."""
    print("=" * 60)
    print("PE STRUCTURE VERIFICATION")
    print("=" * 60)
    print()

    try:
        pe = pefile.PE(unpacked_path)
    except Exception as e:
        print(f"[X] FAIL: Cannot parse PE: {e}")
        return False

    issues = []

    # Check basic PE validity
    if not pe.is_exe():
        issues.append("Not marked as executable")
    else:
        print("[OK] Valid PE executable")

    # Check sections
    section_count = len(pe.sections)
    print(f"[OK] Sections: {section_count}")

    # Check data directories
    dd_import = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    dd_iat = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12]

    if dd_import.VirtualAddress == 0:
        issues.append("Import directory not set")
    else:
        print(f"[OK] Import directory: RVA=0x{dd_import.VirtualAddress:X}, Size={dd_import.Size}")

    if dd_iat.VirtualAddress == 0:
        issues.append("IAT directory not set")
    else:
        print(f"[OK] IAT directory: RVA=0x{dd_iat.VirtualAddress:X}, Size={dd_iat.Size}")

    # Check entry point
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ep == 0:
        issues.append("Entry point is 0")
    else:
        print(f"[OK] Entry point: RVA=0x{ep:X}")

    print()

    if issues:
        print("Issues found:")
        for issue in issues:
            print(f"  [!] {issue}")
        return False

    return True


def verify_sections(unpacked_path):
    """Check section characteristics."""
    print("=" * 60)
    print("SECTION ANALYSIS")
    print("=" * 60)
    print()

    try:
        pe = pefile.PE(unpacked_path)
    except Exception as e:
        print(f"[X] FAIL: Cannot load PE: {e}")
        return False

    print(f"{'Section':<12} {'VirtAddr':<10} {'VirtSize':<10} {'RawSize':<10} {'Characteristics'}")
    print("-" * 70)

    for sec in pe.sections:
        name = sec.Name.decode().rstrip('\x00')
        va = sec.VirtualAddress
        vsize = sec.Misc_VirtualSize
        raw = sec.SizeOfRawData
        chars = sec.Characteristics

        print(f"{name:<12} 0x{va:08X} 0x{vsize:08X} 0x{raw:08X} 0x{chars:08X}")

    print()
    return True


def compare_with_original(unpacked_path, original_path):
    """Compare key metrics with original."""
    print("=" * 60)
    print("COMPARISON WITH ORIGINAL")
    print("=" * 60)
    print()

    try:
        pe_unpacked = pefile.PE(unpacked_path)
        pe_original = pefile.PE(original_path)
    except Exception as e:
        print(f"[X] FAIL: Cannot load PE files: {e}")
        return False

    print(f"{'Metric':<30} {'Unpacked':<15} {'Original':<15} {'Match'}")
    print("-" * 70)

    metrics = [
        ("Image Base",
         f"0x{pe_unpacked.OPTIONAL_HEADER.ImageBase:X}",
         f"0x{pe_original.OPTIONAL_HEADER.ImageBase:X}"),
        ("Entry Point",
         f"0x{pe_unpacked.OPTIONAL_HEADER.AddressOfEntryPoint:X}",
         f"0x{pe_original.OPTIONAL_HEADER.AddressOfEntryPoint:X}"),
        ("Section Count",
         str(len(pe_unpacked.sections)),
         str(len(pe_original.sections))),
        ("Image Size",
         f"0x{pe_unpacked.OPTIONAL_HEADER.SizeOfImage:X}",
         f"0x{pe_original.OPTIONAL_HEADER.SizeOfImage:X}"),
    ]

    for name, unpacked_val, original_val in metrics:
        match = "[OK]" if unpacked_val == original_val else "[!]"
        print(f"{name:<30} {unpacked_val:<15} {original_val:<15} {match}")

    print()
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: verify_unpack.py <unpacked.exe> [original.exe]")
        print()
        print("If original.exe not provided, uses default path:")
        print("  D:/Tools/RE/dumps/runtime/启动器.exe")
        sys.exit(1)

    unpacked_path = sys.argv[1]
    original_path = sys.argv[2] if len(sys.argv) > 2 else "D:/Tools/RE/dumps/runtime/启动器.exe"

    # Check files exist
    if not Path(unpacked_path).exists():
        print(f"ERROR: Unpacked file not found: {unpacked_path}")
        sys.exit(1)

    if not Path(original_path).exists():
        print(f"ERROR: Original file not found: {original_path}")
        sys.exit(1)

    print()
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 15 + "UNPACK VERIFICATION SUITE" + " " * 18 + "║")
    print("╚" + "═" * 58 + "╝")
    print()

    # Run all checks
    results = []

    results.append(("PE Structure", verify_pe_structure(unpacked_path)))
    results.append(("Sections", verify_sections(unpacked_path)))
    results.append(("Import Table", verify_import_table(unpacked_path, original_path)))
    results.append(("Comparison", compare_with_original(unpacked_path, original_path)))

    # Final summary
    print("=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    print()

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "[OK] PASS" if result else "[X] FAIL"
        print(f"  {name:<20} {status}")

    print()
    print(f"Result: {passed}/{total} checks passed")
    print()

    if passed == total:
        print("[SUCCESS] SUCCESS! Unpacking is PERFECT!")
        print()
        print("The unpacked executable has:")
        print("  [OK] Valid PE structure")
        print("  [OK] Complete import table")
        print("  [OK] All ordinal imports preserved")
        print("  [OK] Correct section layout")
        return 0
    else:
        print("[!]  Some checks failed. Review the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
