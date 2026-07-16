#!/usr/bin/env python3
"""Compare .data sections between original and dumped PE files."""

import pefile
import sys

def compare_data_sections(original_path, dumped_path):
    """Compare .data sections of two PE files."""
    print(f"Loading original: {original_path}")
    try:
        original = pefile.PE(original_path)
    except Exception as e:
        print(f"ERROR loading original: {e}")
        return

    print(f"Loading dumped: {dumped_path}")
    try:
        dumped = pefile.PE(dumped_path)
    except Exception as e:
        print(f"ERROR loading dumped: {e}")
        return

    # Find .data sections
    orig_data = None
    dump_data = None
    orig_section = None
    dump_section = None

    print("\n=== Original PE sections ===")
    for s in original.sections:
        name = s.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        print(f"  {name}: VA=0x{s.VirtualAddress:x}, VSize=0x{s.Misc_VirtualSize:x}, RawSize=0x{s.SizeOfRawData:x}")
        if name.startswith('.data'):
            orig_data = s.get_data()
            orig_section = s
            print(f"    -> Found .data: {len(orig_data)} bytes")

    print("\n=== Dumped PE sections ===")
    for s in dumped.sections:
        name = s.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        print(f"  {name}: VA=0x{s.VirtualAddress:x}, VSize=0x{s.Misc_VirtualSize:x}, RawSize=0x{s.SizeOfRawData:x}")
        if name.startswith('.data'):
            dump_data = s.get_data()
            dump_section = s
            print(f"    -> Found .data: {len(dump_data)} bytes")

    if not orig_data:
        print("\nERROR: No .data section found in original PE")
        return

    if not dump_data:
        print("\nERROR: No .data section found in dumped PE")
        return

    # Compare sizes
    print(f"\n=== .data Section Comparison ===")
    print(f"Original .data size: {len(orig_data)} bytes")
    print(f"Dumped .data size:   {len(dump_data)} bytes")

    # Compare content
    min_len = min(len(orig_data), len(dump_data))
    diff_count = sum(1 for i in range(min_len) if orig_data[i] != dump_data[i])

    print(f"\nDifferences in first {min_len} bytes: {diff_count}")
    print(f"Difference percentage: {diff_count * 100.0 / min_len:.2f}%")

    if diff_count > 1000:
        print("\n⚠️  WARNING: .data差异过大，可能dump时.data未初始化")
    elif diff_count > 100:
        print("\n⚠️  CAUTION: .data有较多差异，可能是正常的运行时变化")
    else:
        print("\n✓ .data差异较小")

    # Show first few differences
    if diff_count > 0:
        print(f"\n=== First 10 differences ===")
        shown = 0
        for i in range(min_len):
            if orig_data[i] != dump_data[i]:
                print(f"  Offset 0x{i:06x}: original=0x{orig_data[i]:02x}, dumped=0x{dump_data[i]:02x}")
                shown += 1
                if shown >= 10:
                    break

    # Check entry point
    print(f"\n=== Entry Point ===")
    print(f"Original EP: 0x{original.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    print(f"Dumped EP:   0x{dumped.OPTIONAL_HEADER.AddressOfEntryPoint:x}")

    # Check TLS
    print(f"\n=== TLS Directory ===")
    if hasattr(original, 'DIRECTORY_ENTRY_TLS'):
        print(f"Original TLS: YES")
        tls = original.DIRECTORY_ENTRY_TLS.struct
        print(f"  StartAddressOfRawData: 0x{tls.StartAddressOfRawData:x}")
        print(f"  EndAddressOfRawData:   0x{tls.EndAddressOfRawData:x}")
        print(f"  AddressOfCallBacks:    0x{tls.AddressOfCallBacks:x}")
    else:
        print(f"Original TLS: NO")

    if hasattr(dumped, 'DIRECTORY_ENTRY_TLS'):
        print(f"Dumped TLS: YES")
        tls = dumped.DIRECTORY_ENTRY_TLS.struct
        print(f"  StartAddressOfRawData: 0x{tls.StartAddressOfRawData:x}")
        print(f"  EndAddressOfRawData:   0x{tls.EndAddressOfRawData:x}")
        print(f"  AddressOfCallBacks:    0x{tls.AddressOfCallBacks:x}")
    else:
        print(f"Dumped TLS: NO")

if __name__ == '__main__':
    original = r'D:\Tools\RE\dumps\runtime\启动器.exe'
    dumped = r'D:\Claude project\magicmida-rs\raw_dump.exe'

    compare_data_sections(original, dumped)
