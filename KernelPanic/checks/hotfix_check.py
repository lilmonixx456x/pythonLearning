import json
from datetime import datetime

from .common import run_command


def fetch_hotfixes():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json -Depth 2",
    ]
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return {"error": stderr or stdout}
    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        return {"error": "Failed to parse hotfix JSON output"}


def parse_latest_date(hotfixes):
    if isinstance(hotfixes, dict) and hotfixes.get("error"):
        return None

    dates = []
    for item in hotfixes:
        raw = str(item.get("InstalledOn", "")).strip()
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y", "%d.%m.%Y %H:%M:%S", "%d.%m.%Y"):
            try:
                dates.append(datetime.strptime(raw, fmt))
                break
            except ValueError:
                continue
    return max(dates).isoformat(timespec="seconds") if dates else None


def run():
    hotfixes = fetch_hotfixes()
    return {"hotfixes": hotfixes, "latest_hotfix": parse_latest_date(hotfixes)}
