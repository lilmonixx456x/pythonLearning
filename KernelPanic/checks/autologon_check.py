import json

from .common import run_command


def run():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';"
        "$props = Get-ItemProperty -Path $path -ErrorAction Stop;"
        "[pscustomobject]@{"
        "AutoAdminLogon = $props.AutoAdminLogon;"
        "DefaultUserName = $props.DefaultUserName;"
        "DefaultDomainName = $props.DefaultDomainName;"
        "DefaultPassword = $props.DefaultPassword"
        "} | ConvertTo-Json -Depth 2",
    ]
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return {"error": stderr or stdout}
    try:
        data = json.loads(stdout) if stdout else {}
    except json.JSONDecodeError:
        return {"error": "Failed to parse AutoLogon JSON output"}

    password = data.get("DefaultPassword")
    enabled = str(data.get("AutoAdminLogon", "")).strip() == "1"
    return {
        "enabled": enabled,
        "default_username": data.get("DefaultUserName"),
        "default_domain": data.get("DefaultDomainName"),
        "password_present": bool(password),
    }
