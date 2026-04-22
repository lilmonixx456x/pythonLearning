import json

from .common import run_command


def run():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-SmbShare | Select-Object Name, Path, Description, FolderEnumerationMode | ConvertTo-Json -Depth 3",
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
        return {"error": "Failed to parse SMB shares JSON output"}
