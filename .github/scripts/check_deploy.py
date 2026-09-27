"""Fail when a binary in the deploy folder imports a DLL that is neither shipped nor part of Windows."""
import os
import pathlib
import sys

import pefile

# Present in System32 on a CI runner because Visual Studio is installed, but not part of Windows itself
MUST_SHIP = ("msvcp140", "vcruntime140", "concrt140")

deploy = pathlib.Path(sys.argv[1])
system32 = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
shipped = {p.name.lower() for p in deploy.rglob("*.dll")}
missing = {}

for binary in [*deploy.rglob("*.exe"), *deploy.rglob("*.dll")]:
    pe = pefile.PE(str(binary), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        name = entry.dll.decode().lower()
        if name in shipped or name.startswith(("api-ms-", "ext-ms-")):
            continue
        if not name.startswith(MUST_SHIP) and (system32 / name).exists():
            continue
        missing.setdefault(name, binary.name)

if missing:
    sys.exit("Missing from deploy folder:\n" + "\n".join(f"  {n}  (e.g. needed by {b})" for n, b in sorted(missing.items())))
print("deploy folder is complete")
