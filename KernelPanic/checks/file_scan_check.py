import os
import re
from pathlib import Path

from .common import check_write_access


TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".ini",
    ".cfg",
    ".conf",
    ".xml",
    ".json",
    ".yml",
    ".yaml",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".rdp",
    ".sql",
}

SUSPICIOUS_NAME_PARTS = (
    "pass",
    "password",
    "pwd",
    "secret",
    "token",
    "cred",
    "login",
    "user",
    "backup",
    "config",
    "connection",
    "database",
)

SUSPICIOUS_CONTENT_PATTERNS = (
    re.compile(r"password\s*[:=]", re.IGNORECASE),
    re.compile(r"passwd\s*[:=]", re.IGNORECASE),
    re.compile(r"pwd\s*[:=]", re.IGNORECASE),
    re.compile(r"user\s*id\s*[:=]", re.IGNORECASE),
    re.compile(r"username\s*[:=]", re.IGNORECASE),
    re.compile(r"login\s*[:=]", re.IGNORECASE),
    re.compile(r"server\s*[:=]", re.IGNORECASE),
    re.compile(r"data source\s*=", re.IGNORECASE),
    re.compile(r"initial catalog\s*=", re.IGNORECASE),
    re.compile(r"uid\s*=", re.IGNORECASE),
    re.compile(r"pwd\s*=", re.IGNORECASE),
    re.compile(r"\\{2}[^\\]+\\", re.IGNORECASE),
)


def run(base_path, max_files=5000):
    findings = []
    scanned = 0
    base = Path(base_path)
    if not base.exists():
        return {"error": f"Path not found: {base_path}"}

    for root, _, files in os.walk(base):
        for name in files:
            scanned += 1
            if scanned > max_files:
                return {"findings": findings, "truncated": True, "scanned": scanned}

            file_path = Path(root) / name
            suffix = file_path.suffix.lower()
            lowered = name.lower()
            hit_reasons = []

            if any(part in lowered for part in SUSPICIOUS_NAME_PARTS):
                hit_reasons.append("suspicious_name")

            if suffix in TEXT_EXTENSIONS:
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")[:20000]
                    for pattern in SUSPICIOUS_CONTENT_PATTERNS:
                        if pattern.search(content):
                            hit_reasons.append("suspicious_content")
                            break
                except Exception:
                    hit_reasons.append("unreadable_text_candidate")

            if hit_reasons:
                findings.append(
                    {
                        "path": str(file_path),
                        "reasons": sorted(set(hit_reasons)),
                        "writable": check_write_access(file_path.parent),
                    }
                )
    return {"findings": findings, "truncated": False, "scanned": scanned}
