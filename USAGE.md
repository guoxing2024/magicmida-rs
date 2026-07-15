# Magicmida-RS Usage Guide

## Quick Start

```bash
# Build the tool
./build.sh

# Unpack a protected executable
./target/release/mida-cli.exe /unpack protected.exe

# Get help
./target/release/mida-cli.exe --help
```

## Commands

### 1. Unpack (`/unpack`)

Automatically unpack a Themida-protected executable.

**Syntax:**
```bash
mida-cli /unpack <input-file> [OPTIONS]
```

**Options:**
- `-o, --output <file>` - Specify output path (default: `<input>U.exe`)
- `--data-sections` - Restore `.rdata` and `.data` sections from process memory
- `--shrink` - Remove Themida-specific sections (default: enabled)
- `--no-shrink` - Keep all sections including Themida ones
- `-v, --verbose` - Enable debug logging

**Examples:**

```bash
# Basic unpack (output: protected_U.exe)
mida-cli /unpack protected.exe

# Custom output path
mida-cli /unpack protected.exe -o unpacked.exe

# Verbose logging
mida-cli /unpack protected.exe --verbose

# Keep all sections
mida-cli /unpack protected.exe --no-shrink

# Restore data sections
mida-cli /unpack protected.exe --data-sections
```

**Output:**
- Creates unpacked executable with reconstructed imports
- Original entry point (OEP) is restored
- IAT (Import Address Table) is rebuilt
- Optionally removes Themida sections for smaller file size

### 2. Dump Process (`/dump-process`)

Dump the devirtualized `.text` section from a running unpacked process.

**Syntax:**
```bash
mida-cli /dump-process <pid> <output-file>
```

**Arguments:**
- `<pid>` - Process ID of running unpacked executable
- `<output-file>` - Path to save the dumped executable

**Example:**

```bash
# First, run the unpacked executable
start unpacked.exe

# Get its PID (using Task Manager or PowerShell Get-Process)
# Then dump the devirtualized code
mida-cli /dump-process 12345 dumped.exe
```

**Use Case:**
- Themida may use code virtualization that unpacks at runtime
- This command captures the final devirtualized state
- Useful for complete static analysis after dynamic unpacking

### 3. Verify (`/verify`)

Verify the structure of an unpacked file against a reference.

**Syntax:**
```bash
mida-cli /verify <unpacked-file> <reference-file>
```

**Arguments:**
- `<unpacked-file>` - The file you unpacked (to verify)
- `<reference-file>` - A known-good reference (clean executable or historical output)

**Example:**

```bash
mida-cli /verify unpacked.exe reference.exe
```

**What It Checks:**
- Architecture (x86 vs x64)
- Entry point (OEP) matches
- Import descriptor structure
- IAT address ranges
- Thunk count and ordering
- Section layout

**Output:**
```
[✓] Verification PASSED
[!] Verification FAILED: Import count mismatch (expected 275, got 273)
```

## Global Options

### Help

Show usage information:

```bash
mida-cli --help      # Full help
mida-cli -h          # Short help
mida-cli help        # Alternative
mida-cli /?          # Windows-style
mida-cli             # No args = help
```

### Version

Show version information:

```bash
mida-cli --version   # Full version
mida-cli -V          # Short version
mida-cli version     # Alternative
```

## Command Variants

All commands support multiple formats for convenience:

```bash
# These are equivalent
mida-cli /unpack file.exe
mida-cli --unpack file.exe
mida-cli unpack file.exe

# These are equivalent
mida-cli /verify a.exe b.exe
mida-cli --verify a.exe b.exe
mida-cli verify a.exe b.exe
```

## Exit Codes

- `0` - Success
- `1` - Error (invalid arguments, unpacking failed, verification failed)

## Logging

### Normal Mode

Shows important progress and results:
```
[*] Attaching debugger...
[*] Scanning for OEP...
[*] Found OEP: 0x00401000
[✓] Unpacking complete: output.exe
```

### Verbose Mode (`-v`)

Shows detailed debug information:
```
[DEBUG] ScyllaHide profile loaded
[DEBUG] BP set at Themida entry: 0x00405A30
[DEBUG] Exception handler triggered: EXCEPTION_SINGLE_STEP
[DEBUG] IAT trace: kernel32.dll!GetModuleHandleW -> 0x00402010
[DEBUG] Import reconstruction: 18 modules, 545 thunks
[✓] Unpacking complete: output.exe
```

## Common Workflows

### Workflow 1: Basic Unpacking

```bash
# 1. Unpack the protected file
./target/release/mida-cli.exe /unpack protected.exe

# 2. Test the unpacked file
./protected_U.exe

# 3. If it works, you're done!
```

### Workflow 2: Unpacking with Verification

```bash
# 1. Unpack
./target/release/mida-cli.exe /unpack protected.exe -v

# 2. Verify against a known-good reference
./target/release/mida-cli.exe /verify protected_U.exe reference.exe

# 3. Test runtime
./protected_U.exe
```

### Workflow 3: Handling Code Virtualization

```bash
# 1. Initial unpack
./target/release/mida-cli.exe /unpack protected.exe

# 2. Run the unpacked file (it may still have virtualized code)
start protected_U.exe

# 3. Get PID (e.g., from Task Manager)
# Let's say PID is 8432

# 4. Dump the devirtualized code
./target/release/mida-cli.exe /dump-process 8432 final.exe

# 5. Now final.exe has fully devirtualized code
```

### Workflow 4: Troubleshooting Failed Unpacks

```bash
# 1. Try with verbose logging
./target/release/mida-cli.exe /unpack protected.exe -v > unpack.log 2>&1

# 2. Check the log for where it failed
cat unpack.log

# 3. Try different options
./target/release/mida-cli.exe /unpack protected.exe --data-sections --no-shrink -v
```

## Tips

### Performance

- Unpacking typically takes 10-60 seconds depending on executable size
- Most time is spent in OEP scanning and IAT reconstruction
- Verbose logging adds minimal overhead

### Output Files

- Default output: `<input>U.exe` (Pascal reference convention)
- Use `-o` to specify custom path
- Unpacker never overwrites the input file

### Compatibility

- **x86**: Fully supported
- **x64**: Fully supported
- **Themida versions**: Tested with 2.x and 3.x
- **Other packers**: Not supported (Themida-specific logic)

### Data Sections

- `--data-sections` captures `.rdata` and `.data` from process memory
- **Use when**: Unpacked file crashes due to missing global data
- **Don't use when**: Executable works without it (keeps file cleaner)
- **Warning**: May capture process-specific runtime state

### Section Shrinking

- Default: `--shrink` removes Themida sections (`.themida`, `.winlice`, etc.)
- Reduces file size significantly (often 30-50%)
- Does not affect functionality of clean unpacked code
- Use `--no-shrink` to preserve original section layout

## Troubleshooting

### "File not found"

```bash
# Use absolute or relative path correctly
./target/release/mida-cli.exe /unpack ./path/to/file.exe

# Or use full path
./target/release/mida-cli.exe /unpack D:/protected.exe
```

### "Unpacking failed"

- Try with `--verbose` to see detailed logs
- Check if file is actually Themida-protected
- Ensure you have admin privileges (debugger requires it)
- Check antivirus isn't blocking the debugger

### "Unpacked file crashes"

- Try with `--data-sections` to restore global data
- Use `/dump-process` to capture runtime state
- Verify structure with `/verify` against known-good reference

### Git Bash path issues with `/verify`

```bash
# Git Bash may mangle Windows paths starting with /
# Use MSYS_NO_PATHCONV=1 environment variable
MSYS_NO_PATHCONV=1 ./target/release/mida-cli.exe /verify unpacked.exe reference.exe
```

## Advanced Usage

### Scripting

```bash
#!/bin/bash
for file in protected/*.exe; do
    echo "Unpacking $file..."
    ./target/release/mida-cli.exe /unpack "$file" --verbose
done
```

### Integration with Other Tools

```bash
# Unpack, then analyze with IDA/Ghidra/x64dbg
./target/release/mida-cli.exe /unpack protected.exe
ida64 protected_U.exe

# Unpack, verify, then test
./target/release/mida-cli.exe /unpack protected.exe && \
./target/release/mida-cli.exe /verify protected_U.exe reference.exe && \
./protected_U.exe
```

## Environment Variables

- `RUST_LOG` - Control Rust logging (e.g., `RUST_LOG=debug`)
- `MSYS_NO_PATHCONV` - Disable Git Bash path mangling (for `/verify`)

## See Also

- [BUILD_GUIDE.md](BUILD_GUIDE.md) - How to build the project
- [README.md](README.md) - Project overview
- [AUDIT_REPORT.md](AUDIT_REPORT.md) - Code quality audit
