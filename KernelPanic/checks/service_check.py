import json
from pathlib import Path

from .common import check_write_access, run_command


SERVICE_ACCOUNT_MARKERS = (
    "LocalSystem",
    "NT AUTHORITY\\SYSTEM",
    "LocalService",
    "NetworkService",
)


def fetch_services():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_Service | "
        "Select-Object Name, DisplayName, StartName, State, StartMode, PathName | "
        "ConvertTo-Json -Depth 3",
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
        return {"error": "Failed to parse services JSON output"}


def run():
    services = fetch_services()
    if isinstance(services, dict) and services.get("error"):
        return services

    findings = []
    for service in services:
        path_name = service.get("PathName") or ""
        start_name = service.get("StartName") or ""
        risk_flags = []

        if any(marker.lower() in start_name.lower() for marker in SERVICE_ACCOUNT_MARKERS):
            risk_flags.append("high_privilege_account")

        expanded = path_name.strip().strip('"')
        exe_path = expanded.split(" -")[0].split(" /")[0].strip('"')
        exe = Path(exe_path) if ":" in exe_path else None

        if exe and exe.exists() and check_write_access(exe.parent):
            risk_flags.append("service_directory_writable")

        if risk_flags:
            findings.append(
                {
                    "name": service.get("Name"),
                    "display_name": service.get("DisplayName"),
                    "start_name": start_name,
                    "state": service.get("State"),
                    "path_name": path_name,
                    "risk_flags": risk_flags,
                }
            )
    return findings
