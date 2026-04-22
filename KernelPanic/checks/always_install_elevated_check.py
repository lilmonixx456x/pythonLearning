import json

from .common import run_command


def run():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$paths = @("
        "'HKLM:\\Software\\Policies\\Microsoft\\Windows\\Installer',"
        "'HKCU:\\Software\\Policies\\Microsoft\\Windows\\Installer'"
        ");"
        "$result = @{};"
        "foreach ($path in $paths) {"
        "  if (Test-Path $path) {"
        "    $value = (Get-ItemProperty -Path $path -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated;"
        "    $result[$path] = $value"
        "  } else {"
        "    $result[$path] = $null"
        "  }"
        "};"
        "$result | ConvertTo-Json -Depth 2",
    ]
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return {"error": stderr or stdout}
    try:
        data = json.loads(stdout) if stdout else {}
    except json.JSONDecodeError:
        return {"error": "Failed to parse AlwaysInstallElevated JSON output"}

    hklm = data.get("HKLM:\\Software\\Policies\\Microsoft\\Windows\\Installer")
    hkcu = data.get("HKCU:\\Software\\Policies\\Microsoft\\Windows\\Installer")
    return {"HKLM": hklm, "HKCU": hkcu, "vulnerable": hklm == 1 and hkcu == 1}
