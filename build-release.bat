@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
cd "D:\Claude project\magicmida-rs"
cargo build --release --bin mida-cli
