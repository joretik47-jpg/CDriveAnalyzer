"""Build a standalone Windows x64 application using Zig 0.14.1.

Example: python build.py /absolute/path/to/zig
Zig bundles the Windows headers, linker and static C++ runtime.
No external C++ packages or runtime installers are required.
"""
from pathlib import Path
import os
import subprocess
import sys

root = Path(__file__).resolve().parent
zig = str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else "zig"
env = os.environ.copy()
env["ZIG_GLOBAL_CACHE_DIR"] = str(root / ".zig-cache-global")
env["ZIG_LOCAL_CACHE_DIR"] = str(root / ".zig-cache")
(root / ".build-tmp").mkdir(exist_ok=True)
env["TMPDIR"] = str(root / ".build-tmp")
subprocess.run([zig, "rc", "/c", "65001", "/fo", "app.res", "app.rc"], cwd=root, env=env, check=True)
subprocess.run([
    zig, "c++", "-target", "x86_64-windows-gnu", "-std=c++17",
    "-O2", "-g0", "-Wall", "-Wextra", "-municode", "-Wl,--subsystem,windows",
    "-Wl,--dynamicbase,--nxcompat,--high-entropy-va,--strip-all", "-static",
    "src/main.cpp", "app.res", "-lcomctl32", "-lshell32", "-lole32", "-luuid",
    "-ladvapi32", "-luser32", "-lgdi32", "-lkernel32", "-o", "CDriveCleaner.exe",
], cwd=root, env=env, check=True)
print(root / "CDriveCleaner.exe")
