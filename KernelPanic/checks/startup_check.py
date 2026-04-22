import os
from pathlib import Path

from .common import check_write_access


def run():
    env = os.environ
    startup_paths = [
        Path(env.get("ProgramData", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path(env.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup" if env.get("APPDATA") else None,
    ]

    results = []
    for path in startup_paths:
        if path and path.exists():
            results.append(
                {
                    "path": str(path),
                    "exists": True,
                    "writable": check_write_access(path),
                    "entries": sorted([item.name for item in path.iterdir()])[:50],
                }
            )
    return results
