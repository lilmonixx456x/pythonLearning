import json

from .common import run_command


def run():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-LocalGroupMember -Group 'Administrators' | "
        "Select-Object Name, ObjectClass, PrincipalSource | ConvertTo-Json -Depth 2",
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
        return {"error": "Failed to parse local administrators JSON output"}
