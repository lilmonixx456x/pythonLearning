import json

from .common import run_command


def run():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$services = Get-Service | Where-Object {"
        "  $_.DisplayName -match 'Kaspersky|Network Agent|KES|Endpoint Security' -or "
        "  $_.Name -match '^avp|^kl|klnagent|kes'"
        "} | Select-Object Name, DisplayName, Status, StartType;"
        "$processes = Get-Process | Where-Object {"
        "  $_.ProcessName -match '^avp$|^klnagent$|^kesl$|kaspersky|kl'"
        "} | Select-Object ProcessName, Id, Path;"
        "$regpaths = @("
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        ");"
        "$products = foreach ($rp in $regpaths) { Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue } | "
        "Where-Object { $_.DisplayName -match 'Kaspersky|KES|Endpoint Security|Network Agent' } | "
        "Select-Object DisplayName, DisplayVersion, Publisher;"
        "[pscustomobject]@{Services=$services;Processes=$processes;Products=$products} | ConvertTo-Json -Depth 4",
    ]
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return {"error": stderr or stdout}
    try:
        return json.loads(stdout) if stdout else {}
    except json.JSONDecodeError:
        return {"error": "Failed to parse Kaspersky JSON output"}
