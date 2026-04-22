import os
from pathlib import Path

from .common import check_write_access


def run():
    seen = set()
    findings = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry:
            continue
        key = entry.lower()
        if key in seen:
            continue
        seen.add(key)
        path = Path(entry)
        if path.exists() and path.is_dir():
            writable = check_write_access(path)
            if writable:
                findings.append({"path": str(path), "writable": True})
    return findings
