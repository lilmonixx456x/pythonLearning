import json

from .common import run_command


def run():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress, LocalPort, OwningProcess | "
        "Sort-Object LocalPort | ConvertTo-Json -Depth 2",
    ]
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return {"error": stderr or stdout}
    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        return {"error": "Failed to parse TCP listener JSON output"}

    interesting_ports = {80, 135, 139, 443, 445, 3389, 5985, 5986, 2049}
    return [entry for entry in data if entry.get("LocalPort") in interesting_ports]
