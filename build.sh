#!/bin/bash
# Build wrapper for magicmida-rs in Git Bash
# Sets up MSVC environment and builds the project

set -e

echo "Setting up MSVC environment..."

# Export MSVC paths for linker
export LIB="C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Tools\\MSVC\\14.44.35207\\lib\\x64;C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.26100.0\\um\\x64;C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.26100.0\\ucrt\\x64"
export LIBPATH="C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Tools\\MSVC\\14.44.35207\\lib\\x64"

echo "Building magicmida-rs..."
cd /d/magicmida-rs
cargo build --release --bin mida-cli

echo ""
echo "Build complete!"
ls -lh target/release/mida-cli.exe
