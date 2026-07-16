# Critical Issue Discovered - 2026-07-16 04:16
## Target Process Exits During Unpacking

### 🚨 Current Problem

**Fatal Error**: Target process exited during OEP observation (exit_code=0x2)

This means:
- The debuggee process crashes **during unpacking** (before dump is created)
- No dump file is actually being created successfully
- All previous test files (test_clean.exe, test_original_imports.exe, etc.) were from OLDER builds
- My recent changes may have broken the unpacking process itself

### 📊 Timeline of Confusion

1. **Session started**: Program crashed with "找不到序数 22" error
2. **Fixed ordinal imports**: Modified code to preserve ordinals from original PE
3. **Tested "fixed" versions**: They ran 5-35 seconds before crashing
4. **BUT**: Those test files were from PREVIOUS builds, not current!
5. **NOW**: Current build can't even complete unpacking - target exits during OEP

### 🔍 Root Cause Analysis

**The real problem**: I've been testing stale artifacts!

When I run `mida-cli.exe unpack` NOW:
- Target process is created
- IAT resolves successfully (after 1000ms)
- Then target process EXITS with code 0x2 during "OEP observation"
- No dump file created
- Fatal error

**What I was testing**:
- Old dump files from earlier in the session
- Those files had their own problems (5-35s crashes)
- But they at least RAN

**What current code does**:
- Can't even complete unpacking
- Target process dies early
- Exit code 0x2 suggests process terminated itself (not access violation)

### 💡 Possible Causes

1. **My recent changes broke something**:
   - Modified `build_import_table_from_original` to assign sequential IAT addresses
   - This happens DURING unpacking, not in the dumped file
   - Maybe this broke the unpacking process itself?

2. **The original process is detecting debugger**:
   - Exit code 0x2 is clean exit
   - Themida anti-debug checks?
   - But why now and not before?

3. **Timing issue**:
   - "OEP observation" suggests waiting for OEP to be reached
   - Process exits before reaching OEP
   - Maybe unpack process has regression?

### 🎯 Next Steps

**CRITICAL**: Need to determine if my changes broke unpacking

1. **Test with git stash**:
   - Stash all changes
   - Try unpacking with original code
   - If works → my changes broke it
   - If fails → original was already broken

2. **If my changes broke it**:
   - Bisect to find which change caused the break
   - Likely culprit: `build_import_table_from_original` modifications
   - That function shouldn't affect runtime unpacking at all!

3. **If original was broken**:
   - Then all previous "successful" tests were meaningless
   - Need to understand what changed in the target process

### 🤔 Key Questions

1. **When did unpacking break?**
   - Was it working at session start?
   - Did I test actual unpacking then?
   - Or only tested pre-existing dump files?

2. **What do the old test files prove?**
   - They run 5-35s before crashing
   - They have 545 functions (not 660 with ordinals)
   - They were from IAT rebuild approach (not original PE imports)
   - They DO load and partially work

3. **Why does target exit with code 0x2?**
   - Clean exit, not crash
   - Suggests intentional termination
   - Anti-debug? License check? Missing dependency?

### 📝 Action Plan

```
STEP 1: Verify current state
→ Stash all changes
→ Try unpacking with original code
→ Determine if regression is from my changes

STEP 2: If my changes broke it
→ Revert problematic changes
→ Keep only the OriginalFirstThunk fix (that was proven good)
→ Re-test unpacking

STEP 3: If original was broken
→ Check git history for when it last worked
→ Investigate target process changes
→ Focus on anti-debug or environment issues

STEP 4: Once unpacking works again
→ Then tackle the ordinal import problem properly
→ One step at a time, verify each change
```

### 🎓 Lesson Learned

> **Always verify the build artifact you're testing is from the current build**
>
> I wasted hours testing old files thinking they were fresh builds.
> The lack of ordinal imports should have been a red flag that
> the files weren't from my "ordinal fix" build.

---

*Discovered: 2026-07-16 04:16 UTC*
*Status: CRITICAL - Unpacking broken*
*Priority: Fix unpacking FIRST, then fix dumps*
