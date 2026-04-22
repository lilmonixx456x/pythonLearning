from pathlib import Path


SEARCH_PATHS = [
    Path(r"C:\Windows\Panther\Unattend.xml"),
    Path(r"C:\Windows\Panther\Unattend\Unattend.xml"),
    Path(r"C:\Windows\Panther\Unattend\Unattend.txt"),
    Path(r"C:\Windows\System32\Sysprep\Unattend.xml"),
    Path(r"C:\Windows\System32\Sysprep\Panther\Unattend.xml"),
]

INDICATORS = ("<AutoLogon>", "<Password>", "<PlainText>true</PlainText>", "<Value>")


def run():
    findings = []
    for path in SEARCH_PATHS:
        if not path.exists():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            findings.append({"path": str(path), "indicators": ["unreadable_file"]})
            continue

        matched = [indicator for indicator in INDICATORS if indicator.lower() in content.lower()]
        if matched:
            findings.append({"path": str(path), "indicators": matched})
    return {"findings": findings}
