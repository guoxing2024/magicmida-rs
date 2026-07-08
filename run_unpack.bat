@echo off
set "VCDIR=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build"
call "%VCDIR%\vcvars64.bat"
cd /d "D:\Claude project\magicmida-rs\target\release"
mida-cli.exe /unpack "D:\Tools\RE\dumps\newproject\时光单开.exe" -o "D:\Tools\RE\dumps\newproject\时光单开U_new.exe" -v
