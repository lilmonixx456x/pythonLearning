import json

from .common import run_command


def run():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordExpires, LastLogon | "
        "ConvertTo-Json -Depth 2",
    ]
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return {"error": stderr or stdout}
    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        return {"error": "Failed to parse local users JSON output"}

    findings = []
    for user in data:
        flags = []
        if user.get("Enabled") is True and user.get("PasswordRequired") is False:
            flags.append("no_password_required")
        if user.get("Enabled") is True and user.get("PasswordExpires") is False:
            flags.append("password_never_expires")
        if flags:
            findings.append(
                {
                    "name": user.get("Name"),
                    "flags": flags,
                    "last_logon": user.get("LastLogon"),
                }
            )
    return findings
