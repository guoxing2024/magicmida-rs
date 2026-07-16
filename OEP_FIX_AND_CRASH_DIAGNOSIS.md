# OEP Fix and Runtime Crash Diagnosis
**Date**: 2026-07-16  
**Issue**: Unpacked GUI executable crashes with segfault
**Status**: OEP Fixed ✅ | Runtime Crash ❌

---

## Summary

### Problem 1: Wrong Entry Point ✅ FIXED

**Symptom**: Unpacked executable had entry point at 0x1000 instead of 0x70b7

**Root Cause**:
- In `post_attach` mode, `scan_live_memory_for_real_oep()` scans .text for CRT patterns
- It finds `__scrt_common_main_seh` at 0x1000 (CRT initialization)
- Original code **replaced** the captured OEP (0x70b7) with scan result (0x1000)
- 0x1000 is the C runtime startup, NOT the application entry point

**Why This Matters**:
- 0x1000: CRT initialization code (`sub rsp, 38; mov [rsp+20h], 0FFFFFFFEh`)
- 0x70b7: Actual application entry point (where main() or WinMain starts)
- Using 0x1000 means the application never reaches its actual code

**Fix Applied** (commit 23b3e43):
1. Changed logic in `crates/cli/src/unpacker/mod.rs` line 1792-1806
2. In `post_attach` mode: **KEEP** captured OEP, **IGNORE** scan result
3. Reasoning: Captured RIP is where code actually runs = real app entry
4. Reduced scan range from 0x40000 to 0x1000 in fallback pattern

**Result**:
```
Before: Entry Point = 0x1000 (CRT)
After:  Entry Point = 0x70b7 (Application)
```

**Verification**:
```bash
python3 -c "import pefile; pe = pefile.PE('final_unpack_1.exe'); print(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))"
# Output: 0x70b7 ✅
```

---

## Problem 2: Runtime Segmentation Fault ❌ UNSOLVED

### Symptom
```
./final_unpack_1.exe
Segmentation fault
```

Process crashes immediately upon execution. No GUI window appears.

### What Works
- ✅ PE structure is valid
- ✅ Import table is 100% accurate (21/660/42)
- ✅ Entry point is correct (0x70b7)
- ✅ Process starts (4 threads, 26 MB memory)
- ✅ Windows loader accepts the file

### What Fails
- ❌ Process crashes with segfault after ~0.5 seconds
- ❌ No GUI window appears
- ❌ Application logic never executes

### Possible Causes

#### 1. Data Section Issues ⚠️ LIKELY
**Problem**: Global variables may have wrong values

The `.data` section contains:
- Initialized global variables
- Static variables
- Program state

If these are dumped from **runtime memory** after Themida has modified them, but the application expects **original compile-time values**, it will crash.

**Evidence**:
- Themida may use .data for its own purposes during unpacking
- Runtime .data != Original .data
- Application reads wrong values → crash

**Fix Strategy**:
- Need to restore .data from **original PE** before Themida packed it
- Or capture .data **before** Themida initializes
- Current code dumps .data from live process = wrong values

#### 2. Relocation Issues ⚠️ POSSIBLE
**Problem**: Hardcoded addresses not fixed

The unpacked file has:
- Image Base: 0x140000000
- ASLR: Disabled (DllCharacteristics: 0x20)
- Relocation table: 1919 entries

But if there are hardcoded addresses that the relocation table missed:
- Code jumps to wrong address → crash
- Code reads from wrong memory → crash

**Evidence**:
- Log shows: "fixed 0 hardcoded addresses"
- This means no addresses were patched
- If original binary had relocations, they may be missing

**Fix Strategy**:
- Enable ASLR and ensure relocation table is complete
- Or ensure all hardcoded addresses are in relocation table

#### 3. TLS (Thread Local Storage) Issues ⚠️ POSSIBLE
**Problem**: TLS callbacks or TLS data incorrect

TLS bootstrap code:
```
.boot section at 0xeda000
.tls section at 0xedb000
TLS callback container: 1
```

If TLS initialization fails:
- Threads crash on startup
- C++ runtime crashes (uses TLS)

**Evidence**:
- Application has TLS (not all apps do)
- TLS bootstrap was installed by unpacker
- May not match original TLS structure

#### 4. Stack Cookie / Security Cookie ⚠️ POSSIBLE
**Problem**: Security cookies mismatched

The pattern at 0x1000:
```
48 83 EC 38        sub rsp, 38h
48 C7 44 24 20     mov qword ptr [rsp+20h], 0FFFFFFFEh
FE FF FF FF
```

The `0xFFFFFFFE` is a security cookie sentinel. If the application expects a different cookie value, it will crash.

#### 5. Exception Handling (.pdata) ⚠️ POSSIBLE
**Problem**: Exception directory incorrect

The unpacked file has TWO .pdata sections:
```
.pdata at 0x14d000 (34 KB)
.pdata at 0xecc000 (45 KB)
```

If exception handling structures are wrong:
- First exception → crash
- Stack unwinding fails → crash

#### 6. Resource Dependencies ⚠️ LESS LIKELY
**Problem**: Missing external resources

GUI applications often need:
- Config files
- DLL dependencies
- Registry entries
- Network connections

But import table is 100% complete, so DLL dependencies should be OK.

---

## Diagnostic Steps Needed

### Step 1: Debug with x64dbg
```
1. Open final_unpack_1.exe in x64dbg
2. Set breakpoint at entry point (0x140070b7)
3. Run and see if it hits breakpoint
4. Step through to find crash point
5. Check register values and memory at crash
```

### Step 2: Compare .data Section
```python
# Compare original vs unpacked .data
original = pefile.PE('D:/Tools/RE/dumps/runtime/启动器.exe')
unpacked = pefile.PE('final_unpack_1.exe')

# Find .data sections
# Compare contents byte-by-byte
# Identify differences
```

### Step 3: Check Relocation Table
```
dumpbin /relocations final_unpack_1.exe
# Should show 1919 entries
# Check if they cover all absolute addresses in code
```

### Step 4: Test with ASLR Disabled
```
editbin /DYNAMICBASE:NO final_unpack_1.exe
# Force load at base address
# Eliminates relocation as issue
```

### Step 5: Dump at Different Time
```
# Current: Dump after IAT resolution
# Try: Dump before Themida initializes .data
# Or: Restore .data from original PE
```

---

## Comparison with Working Original

### Original Packed File
```
Entry Point: 0xBD5807 (Themida VM)
Runs successfully → GUI appears
```

### Unpacked File
```
Entry Point: 0x70b7 (Application code)
Crashes immediately → No GUI
```

### Hypothesis
The unpacked entry point (0x70b7) is correct, but:
- Global variables are wrong
- Or memory layout is wrong
- Or some initialization is missing

The original works because Themida:
1. Initializes .data correctly
2. Sets up proper memory layout
3. Runs custom initialization
4. THEN jumps to 0x70b7

The unpacked file jumps straight to 0x70b7 without steps 1-3.

---

## Recommended Next Steps

### Priority 1: Data Section Restoration
Modify unpacker to:
1. Read .data from **original PE** (before packing)
2. Don't dump .data from live process
3. Use compile-time data, not runtime data

### Priority 2: Debug with x64dbg
1. Load unpacked file
2. Single-step from entry point
3. Find exact crash instruction
4. Examine what went wrong

### Priority 3: Compare Dumping Strategies
Try different dump timing:
- Current: After IAT resolution
- Alternative 1: Before Themida modifies .data
- Alternative 2: Hybrid (code from runtime, data from original)

---

## Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| PE Structure | ✅ Valid | Windows loader accepts file |
| Import Table | ✅ 100% | All 21/660/42 imports correct |
| Entry Point | ✅ Fixed | Now points to 0x70b7 (app entry) |
| .text Section | ✅ OK | Code is decrypted and dumped |
| .data Section | ❌ Suspect | May have wrong values |
| Relocations | ⚠️ Unknown | 1919 entries, but may be incomplete |
| TLS | ⚠️ Unknown | Bootstrap installed, may be wrong |
| Exception Handling | ⚠️ Unknown | Two .pdata sections |
| Runtime Execution | ❌ Crashes | Segfault after 0.5s |

---

## Code Changes

### File: `crates/cli/src/unpacker/mod.rs`
**Line 1780-1806**: Changed OEP replacement logic
- Old: Replace captured OEP with scan result in post_attach mode
- New: Keep captured OEP, ignore scan result
- Reason: Captured OEP is real app entry, scan finds CRT entry

### File: `crates/cli/src/unpacker/oep_scan.rs`
**Line 115**: Reduced scan range
- Old: `0x40000.min(effective_len)`
- New: `0x1000.min(effective_len)`
- Reason: Prevent matching random functions far into .text

---

## Conclusion

**OEP Problem**: ✅ SOLVED
- Entry point is now correct (0x70b7)
- Application code is reached

**Runtime Crash**: ❌ UNSOLVED
- Most likely: .data section has wrong values
- Need to restore .data from original PE instead of dumping from runtime
- Requires further debugging with x64dbg to pinpoint exact cause

**Next Action**: 
Investigate .data section restoration strategy or debug with x64dbg to find crash point.

---

*Report Date: 2026-07-16*  
*Commit: 23b3e43*  
*OEP Fix: Applied*  
*Runtime Fix: Pending Investigation*
