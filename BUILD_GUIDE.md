# Magicmida-RS Build Guide

## Problem: Git Bash Linker Conflict

When building Rust projects in Git Bash on Windows, you may encounter linker errors like:

```
error: linking with `link.exe` failed: exit code: 1
link: missing operand after '\377\376'
Try 'link --help' for more information.
```

**Root Cause**: Git Bash includes `/usr/bin/link.exe`, which is a Unix symlink utility, not the MSVC linker. When Cargo searches for `link.exe` in Git Bash, it finds this incorrect tool first.

## Solution

This project includes a pre-configured build system that avoids the conflict:

### Option 1: Use the Build Script (Recommended)

```bash
cd /d/magicmida-rs
./build.sh
```

The `build.sh` script:
- Sets up MSVC environment variables (`LIB`, `LIBPATH`)
- Explicitly configures the correct linker path
- Builds the release binary

### Option 2: Use CMD/PowerShell

Build directly in CMD or PowerShell where Git Bash's `link.exe` isn't in PATH:

```cmd
cd D:\magicmida-rs
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
cargo build --release --bin mida-cli
```

### Option 3: Cargo Configuration

The project includes `.cargo/config.toml` with explicit linker configuration:

```toml
[target.x86_64-pc-windows-msvc]
linker = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\link.exe"
```

This works when you set the `LIB` environment variable (done automatically by `build.sh`).

## Verification

After building, test the executable:

```bash
./target/release/mida-cli.exe --version   # Show version
./target/release/mida-cli.exe --help      # Show help
```

## CLI Features

### Standard Options Now Supported

- `--help`, `-h`, `/?`, `help` - Show help message
- `--version`, `-V`, `version` - Show version
- No arguments - Show help (instead of error)

### Commands

- `/unpack <file>` - Unpack Themida-protected executable
- `/dump-process <pid> <file>` - Dump devirtualized .text section
- `/verify <unpacked> <reference>` - Verify unpacked file structure

### Examples

```bash
# Basic unpack
./target/release/mida-cli.exe /unpack protected.exe

# Unpack with custom output and verbose logging
./target/release/mida-cli.exe /unpack app.exe -o unpacked.exe --verbose

# Verify unpacked file against reference
./target/release/mida-cli.exe /verify unpacked.exe reference.exe
```

## Technical Details

### Why This Happens

1. Git Bash adds `/usr/bin` to PATH
2. `/usr/bin/link.exe` is a Unix tool for creating hard links
3. Cargo searches PATH for `link.exe` and finds the wrong one
4. MSVC linker arguments are passed to Unix `link`, causing errors

### The Fix

- Explicitly specify MSVC linker path in `.cargo/config.toml`
- Set `LIB` environment variable so linker can find Windows SDK libraries
- Use `build.sh` wrapper script that handles environment setup

### Verification of the Issue

```bash
# Git Bash finds Unix link
$ which link.exe
/usr/bin/link.exe

# CMD/PowerShell finds MSVC link
> where link.exe
C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe
```

## Alternative Solutions

If you encounter linker issues in other Rust projects:

1. **Remove Git Bash's link.exe from PATH** (not recommended - breaks other tools)
2. **Build in CMD/PowerShell instead of Git Bash**
3. **Use cargo wrapper scripts that set up MSVC environment**
4. **Configure explicit linker in `.cargo/config.toml`**

## Requirements

- Visual Studio 2022 with C++ build tools
- Rust toolchain (MSVC target)
- Windows SDK 10.0.26100.0 or later

## Troubleshooting

### "cannot open input file kernel32.lib"

The linker is correct but can't find Windows SDK libraries. Set the `LIB` environment variable:

```bash
export LIB="C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Tools\\MSVC\\14.44.35207\\lib\\x64;C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.26100.0\\um\\x64;C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.26100.0\\ucrt\\x64"
```

Or use `build.sh` which does this automatically.

### Linker path changed after Visual Studio update

Update `.cargo/config.toml` with the new MSVC version path. Find it with:

```bash
find "/c/Program Files/Microsoft Visual Studio" -name "link.exe" -path "*/Hostx64/x64/link.exe"
```

## References

- [Rust issue #55093](https://github.com/rust-lang/rust/issues/55093) - Git Bash link.exe conflict
- [Cargo book - Configuration](https://doc.rust-lang.org/cargo/reference/config.html)
