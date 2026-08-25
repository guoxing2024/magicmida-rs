import subprocess, os
# find MSVC link.exe directly
roots = [r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools", r"C:\Program Files\Microsoft Visual Studio\2022\Professional"]
found = []
for root in roots:
    for dirpath, dirnames, filenames in os.walk(root):
        if "link.exe" in filenames and "x64" in dirpath and "Hostx64" in dirpath.replace("\\","/"):
            found.append(os.path.join(dirpath, "link.exe"))
        if len(found) > 10: break
    if len(found) > 10: break
print("FOUND:", found[:10])