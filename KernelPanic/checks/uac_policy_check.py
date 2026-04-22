import json

from .common import run_command


def run():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$path='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';"
        "$props=Get-ItemProperty -Path $path -ErrorAction Stop;"
        "[pscustomobject]@{"
        "EnableLUA=$props.EnableLUA;"
        "ConsentPromptBehaviorAdmin=$props.ConsentPromptBehaviorAdmin;"
        "LocalAccountTokenFilterPolicy=$props.LocalAccountTokenFilterPolicy;"
        "FilterAdministratorToken=$props.FilterAdministratorToken"
        "} | ConvertTo-Json -Depth 2",
    ]
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return {"error": stderr or stdout}
    try:
        data = json.loads(stdout) if stdout else {}
    except json.JSONDecodeError:
        return {"error": "Failed to parse UAC policy JSON output"}

    findings = []
    if data.get("EnableLUA") == 0:
        findings.append("uac_disabled")
    if data.get("ConsentPromptBehaviorAdmin") == 0:
        findings.append("no_admin_prompt")
    if data.get("LocalAccountTokenFilterPolicy") == 1:
        findings.append("remote_uac_restrictions_relaxed")
    return {"values": data, "findings": findings}
