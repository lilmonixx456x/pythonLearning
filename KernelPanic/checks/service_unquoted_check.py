import json

from .common import run_command


def run():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_Service | "
        "Select-Object Name, DisplayName, StartName, PathName | ConvertTo-Json -Depth 3",
    ]
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return {"error": stderr or stdout}
    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        return {"error": "Failed to parse services JSON output"}

    findings = []
    for item in data:
        path_name = (item.get("PathName") or "").strip()
        lowered = path_name.lower()
        if " " in path_name and ".exe" in lowered and not path_name.startswith('"'):
            findings.append(
                {
                    "name": item.get("Name"),
                    "display_name": item.get("DisplayName"),
                    "start_name": item.get("StartName"),
                    "path_name": path_name,
                }
            )
    return findings
