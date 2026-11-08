"""Inspect the Windows PE, its resources and runtime imports without executing it."""
from pathlib import Path
import hashlib
import json
import struct
import sys

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "CDriveCleaner.exe"
data = path.read_bytes()
u16 = lambda off: struct.unpack_from("<H", data, off)[0]
u32 = lambda off: struct.unpack_from("<I", data, off)[0]
assert data[:2] == b"MZ"
pe = u32(0x3C)
assert data[pe:pe + 4] == b"PE\0\0"
assert u16(pe + 4) == 0x8664, "Expected Windows x64"
count, optional_size = u16(pe + 6), u16(pe + 20)
opt = pe + 24
assert u16(opt) == 0x20B, "Expected PE32+"
assert u16(opt + 68) == 2, "Expected a native GUI application"
flags = u16(opt + 70)
assert flags & 0x160 == 0x160, "ASLR, high-entropy VA and NX must be enabled"
sections = []
for i in range(count):
    pos = opt + optional_size + i * 40
    name = data[pos:pos + 8].rstrip(b"\0").decode("ascii")
    virtual_size, va, raw_size, raw = struct.unpack_from("<IIII", data, pos + 8)
    sections.append((name, va, max(virtual_size, raw_size), raw, raw_size, u32(pos + 36)))

def offset(rva):
    for name, va, size, raw, raw_size, attrs in sections:
        if va <= rva < va + raw_size:
            return raw + rva - va
    raise AssertionError(f"Unbacked RVA: {rva:x}")

def text_at(rva):
    start = offset(rva)
    return data[start:data.index(b"\0", start)].decode("ascii")

entry = u32(opt + 16)
assert any(va <= entry < va + size and attrs & 0x20000000 for _, va, size, _, _, attrs in sections)
directories = [struct.unpack_from("<II", data, opt + 112 + i * 8) for i in range(16)]
assert directories[2][0] and directories[3][0] and directories[5][0], "Resources, unwind data and relocations must exist"
assert directories[14] == (0, 0), "Not a managed .NET launcher"
assert directories[4] == (0, 0), "Release is intentionally described as unsigned"
pos = offset(directories[1][0])
imports = []
while True:
    row = struct.unpack_from("<IIIII", data, pos)
    if not any(row):
        break
    imports.append(text_at(row[3]))
    pos += 20
allowed = {"kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll", "comctl32.dll", "ole32.dll"}
assert all(d.lower() in allowed or d.lower().startswith("api-ms-win-crt-") for d in imports), imports
assert b'requestedExecutionLevel level="asInvoker"' in data
assert b'Microsoft.Windows.Common-Controls' in data
assert b'SetFileInformationByHandle\0' in data
assert b'GetFinalPathNameByHandleW\0' in data
for forbidden in (b'DeleteFileW\0', b'RemoveDirectoryW\0', b'SHFileOperationW\0'):
    assert forbidden not in data, forbidden
report = {
    "result": "PASS",
    "file": path.name,
    "bytes": len(data),
    "sha256": hashlib.sha256(data).hexdigest(),
    "architecture": "Windows x64 / PE32+ / GUI",
    "ASLR_NX_high_entropy": True,
    "manifest": "asInvoker; common controls v6",
    "runtime_DLLs": imports,
    "execution_test": "NOT RUN: no Windows or Wine runtime available",
}
print(json.dumps(report, indent=2, ensure_ascii=False))
