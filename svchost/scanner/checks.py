import os
import re
from pathlib import Path

from .acl import extract_candidate_hijack_paths, find_writable_parent, get_identity_context, has_unquoted_space_path
from .system import (
    csv_from_text,
    existing_paths,
    expand_env_path,
    first_existing_parent,
    normalized_path,
    powershell_json,
    read_text_file,
    run_command,
    run_powershell,
    split_command_path,
)


SUSPICIOUS_FILE_NAMES = (
    "pass",
    "pwd",
    "cred",
    "secret",
    "token",
    "config",
    "backup",
    "connection",
    "rdp",
)
SUSPICIOUS_EXTENSIONS = {".txt", ".ini", ".xml", ".config", ".conf", ".rdp", ".ps1", ".bat", ".cmd", ".vbs", ".log"}
SUSPICIOUS_CONTENT = (
    "password=",
    "pwd=",
    "passwd=",
    "username=",
    "user id=",
    "data source=",
    "defaultpassword",
    "autoadminlogon",
    "cpassword",
)


def severity(score):
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def make_finding(check_id, title, level, evidence, risk, path=""):
    return {
        "check": check_id,
        "title": title,
        "level": level,
        "evidence": evidence,
        "risk": risk,
        "path": path,
    }


def check_hotfixes():
    data = powershell_json(
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object HotFixID, InstalledOn, Description | ConvertTo-Json -Depth 2"
    )
    findings = []
    latest = None
    if isinstance(data, dict) and data.get("error"):
        findings.append(make_finding("hotfix", "Hotfix inventory unavailable", "medium", data["error"], "patch_level_unknown"))
        return {"findings": findings, "meta": {"latest_hotfix": None}}

    if data:
        latest = str(data[0].get("InstalledOn", "")).strip()
        hotfix_ids = [item.get("HotFixID") for item in data[:5] if item.get("HotFixID")]
        findings.append(
            make_finding(
                "hotfix",
                "Patch level snapshot",
                "info",
                f"Latest installed update: {latest}; recent KBs: {', '.join(hotfix_ids)}",
                "manual_age_review_required",
            )
        )
    return {"findings": findings, "meta": {"latest_hotfix": latest}}


def check_registry_misconfig():
    findings = []
    registry_checks = [
        (
            "AlwaysInstallElevated HKLM",
            ["reg", "query", r"HKLM\Software\Policies\Microsoft\Windows\Installer", "/v", "AlwaysInstallElevated"],
            "1",
            "always_install_elevated_hklm",
        ),
        (
            "AlwaysInstallElevated HKCU",
            ["reg", "query", r"HKCU\Software\Policies\Microsoft\Windows\Installer", "/v", "AlwaysInstallElevated"],
            "1",
            "always_install_elevated_hkcu",
        ),
        (
            "AutoAdminLogon",
            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "/v", "AutoAdminLogon"],
            "0x1",
            "autoadminlogon_enabled",
        ),
        (
            "DefaultPassword",
            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "/v", "DefaultPassword"],
            None,
            "autologon_password_present",
        ),
        (
            "EnableLUA",
            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "EnableLUA"],
            "0x0",
            "uac_disabled",
        ),
        (
            "LocalAccountTokenFilterPolicy",
            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "LocalAccountTokenFilterPolicy"],
            "0x1",
            "remote_uac_relaxed",
        ),
    ]

    values = {}
    for title, cmd, expected, risk in registry_checks:
        code, stdout, stderr = run_command(cmd)
        output = (stdout or stderr).strip()
        values[title] = output
        if code == 0:
            if expected is None and title == "DefaultPassword":
                findings.append(make_finding("registry", title, "critical", output, risk))
            elif expected and expected.lower() in output.lower():
                level = "critical" if "Password" in title or "AlwaysInstall" in title else "high"
                findings.append(make_finding("registry", title, level, output, risk))

    hklm = values.get("AlwaysInstallElevated HKLM", "")
    hkcu = values.get("AlwaysInstallElevated HKCU", "")
    if "0x1" in hklm.lower() and "0x1" in hkcu.lower():
        findings.append(
            make_finding(
                "registry",
                "AlwaysInstallElevated fully enabled",
                "critical",
                "Both HKLM and HKCU policy values are 1",
                "msi_privilege_escalation_path",
            )
        )
    return {"findings": findings, "meta": values}


def check_unattend_and_gpp(domain):
    findings = []
    paths = [
        r"C:\Windows\Panther\Unattend.xml",
        r"C:\Windows\Panther\Unattend\Unattend.xml",
        r"C:\Windows\System32\Sysprep\Unattend.xml",
        r"C:\Windows\System32\Sysprep\Panther\Unattend.xml",
    ]
    if domain:
        paths.extend(
            [
                fr"\\{domain}\SYSVOL",
                fr"\\{domain.lower()}\SYSVOL",
            ]
        )

    for path in paths:
        if not Path(path).exists():
            continue
        if Path(path).is_dir():
            for root, _, files in os.walk(path):
                for name in files:
                    lowered = name.lower()
                    if lowered == "groups.xml" or lowered.endswith(".xml"):
                        full_path = str(Path(root) / name)
                        content = read_text_file(full_path, 20000).lower()
                        markers = [marker for marker in ("cpassword", "autologon", "defaultpassword", "<password>", "<plaintext>true</plaintext>") if marker in content]
                        if markers:
                            findings.append(make_finding("gpp", "Sensitive XML in SYSVOL", "critical", f"{full_path} | markers={', '.join(markers)}", "credential_material_exposed", full_path))
                if len(findings) >= 20:
                    return {"findings": findings, "meta": {"searched": paths}}
        else:
            content = read_text_file(path, 20000).lower()
            markers = [marker for marker in ("autologon", "defaultpassword", "<password>", "<plaintext>true</plaintext>") if marker in content]
            if markers:
                findings.append(make_finding("unattend", "Sensitive unattend material", "critical", f"{path} | markers={', '.join(markers)}", "credential_material_exposed", path))

    return {"findings": findings, "meta": {"searched": paths}}


def check_services(identity):
    findings = []
    data = powershell_json(
        "Get-CimInstance Win32_Service | "
        "Select-Object Name, DisplayName, StartName, State, PathName | ConvertTo-Json -Depth 3"
    )
    if isinstance(data, dict) and data.get("error"):
        return {"findings": [make_finding("service", "Service enumeration failed", "medium", data["error"], "coverage_gap")], "meta": {}}

    for item in data:
        command_line = (item.get("PathName") or "").strip()
        image_path, _ = split_command_path(command_line)
        start_name = item.get("StartName") or ""
        privileged = any(token in start_name.lower() for token in ("localsystem", "localservice", "networkservice", "nt authority"))

        if has_unquoted_space_path(command_line) and privileged:
            findings.append(
                make_finding(
                    "service",
                    "Unquoted privileged service path",
                    "high",
                    f"{item.get('Name')} | {command_line}",
                    "service_path_hijack",
                    image_path or command_line,
                )
            )
            for candidate in extract_candidate_hijack_paths(command_line):
                parent_check = find_writable_parent(first_existing_parent(candidate) or candidate, identity)
                if parent_check["writable"]:
                    findings.append(
                        make_finding(
                            "service",
                            "Writable path in unquoted service chain",
                            "critical",
                            f"{item.get('Name')} | candidate={candidate} | acl={parent_check['reason']}",
                            "high_confidence_service_hijack",
                            candidate,
                        )
                    )

        if image_path and privileged:
            parent = first_existing_parent(image_path)
            if parent:
                acl = find_writable_parent(parent, identity)
                if acl["writable"]:
                    findings.append(
                        make_finding(
                            "service",
                            "Privileged service in writable location",
                            "critical",
                            f"{item.get('Name')} | {image_path} | acl={acl['reason']}",
                            "service_binary_replacement_or_drop",
                            image_path,
                        )
                    )
    return {"findings": findings, "meta": {"count": len(data)}}


def _extract_task_exec(command):
    if not command:
        return ""
    command = command.strip()
    if command.startswith('"'):
        end = command.find('"', 1)
        if end > 1:
            return normalized_path(command[1:end])
    if re.match(r"^[A-Za-z]:\\", command):
        return normalized_path(command.split(" ")[0])
    return ""


def check_tasks(identity):
    findings = []
    code, stdout, stderr = run_command(["schtasks", "/query", "/fo", "csv", "/v"])
    if code != 0:
        return {"findings": [make_finding("task", "Scheduled task enumeration failed", "medium", (stderr or stdout).strip(), "coverage_gap")], "meta": {}}

    rows = csv_from_text(stdout)
    for row in rows:
        run_as = (row.get("Run As User") or "").lower()
        task_name = row.get("TaskName") or ""
        task_to_run = row.get("Task To Run") or row.get("Actions") or ""
        if not task_to_run:
            continue
        privileged = any(token in run_as for token in ("system", "administrator", "service"))
        exec_path = _extract_task_exec(task_to_run)

        if privileged and has_unquoted_space_path(task_to_run):
            findings.append(make_finding("task", "Unquoted privileged task action", "high", f"{task_name} | {task_to_run}", "task_path_hijack", exec_path or task_to_run))

        if privileged and exec_path:
            parent = first_existing_parent(exec_path)
            if parent:
                acl = find_writable_parent(parent, identity)
                if acl["writable"]:
                    findings.append(
                        make_finding(
                            "task",
                            "Privileged task points to writable location",
                            "critical",
                            f"{task_name} | {exec_path} | acl={acl['reason']}",
                            "task_binary_replacement_or_script_swap",
                            exec_path,
                        )
                    )
    return {"findings": findings, "meta": {"count": len(rows)}}


def check_autoruns(identity):
    findings = []
    startup_dirs = existing_paths(
        [
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            expand_env_path(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
    )
    for startup_dir in startup_dirs:
        acl = find_writable_parent(startup_dir, identity)
        if acl["writable"]:
            findings.append(make_finding("autorun", "Writable Startup folder", "high", f"{startup_dir} | acl={acl['reason']}", "autorun_drop_path", startup_dir))

    run_keys = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    for key in run_keys:
        code, stdout, _ = run_command(["reg", "query", key])
        if code != 0:
            continue
        for line in stdout.splitlines():
            if "REG_" not in line:
                continue
            parts = re.split(r"\s{2,}", line.strip(), maxsplit=2)
            if len(parts) < 3:
                continue
            value_data = parts[2]
            exec_path, _ = split_command_path(expand_env_path(value_data))
            if exec_path:
                parent = first_existing_parent(exec_path)
                if parent:
                    acl = find_writable_parent(parent, identity)
                    if acl["writable"]:
                        findings.append(
                            make_finding(
                                "autorun",
                                "Autorun points to writable location",
                                "high",
                                f"{key} | {value_data} | acl={acl['reason']}",
                                "autorun_binary_swap",
                                exec_path,
                            )
                        )
    return {"findings": findings, "meta": {"startup_dirs": startup_dirs}}


def check_path_hijack(identity):
    findings = []
    seen = set()
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        expanded = expand_env_path(entry)
        if not expanded:
            continue
        lowered = expanded.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        if not Path(expanded).exists():
            continue
        acl = find_writable_parent(expanded, identity)
        if acl["writable"]:
            findings.append(make_finding("path", "Writable PATH directory", "high", f"{expanded} | acl={acl['reason']}", "path_hijack", expanded))
    return {"findings": findings, "meta": {"count": len(seen)}}


def check_file_loot(target):
    findings = []
    roots = [target, r"C:\ProgramData"]
    for root in roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        scanned = 0
        for base, _, files in os.walk(root):
            for name in files:
                scanned += 1
                if scanned > 4000:
                    return {"findings": findings, "meta": {"truncated": True}}
                full_path = str(Path(base) / name)
                lowered = name.lower()
                if not any(part in lowered for part in SUSPICIOUS_FILE_NAMES) and Path(name).suffix.lower() not in SUSPICIOUS_EXTENSIONS:
                    continue
                content = read_text_file(full_path, 12000).lower()
                markers = [token for token in SUSPICIOUS_CONTENT if token in content]
                if markers:
                    findings.append(make_finding("files", "Interesting file with credential markers", "medium", f"{full_path} | markers={', '.join(markers)}", "possible_credentials_or_config", full_path))
    return {"findings": findings, "meta": {"roots": roots}}


def check_local_identity():
    findings = []
    code, stdout, stderr = run_command(["whoami", "/priv"])
    output = (stdout or stderr).strip()
    if code == 0 and output:
        for privilege in ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"):
            if privilege in output:
                findings.append(make_finding("token", "Interesting user privilege present", "high", privilege, "local_privilege_path"))
    return {"findings": findings, "meta": {}}


def check_kaspersky():
    findings = []
    products = powershell_json(
        "$reg='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*';"
        "$reg2='HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*';"
        "Get-ItemProperty -Path $reg,$reg2 -ErrorAction SilentlyContinue | "
        "Where-Object {$_.DisplayName -match 'Kaspersky|KES|Endpoint Security|Network Agent'} | "
        "Select-Object DisplayName, DisplayVersion, Publisher | ConvertTo-Json -Depth 2"
    )
    if isinstance(products, dict) and products.get("error"):
        products = []
    for item in products:
        findings.append(make_finding("kaspersky", "Kaspersky product detected", "info", f"{item.get('DisplayName')} {item.get('DisplayVersion') or ''}", "defensive_stack_present"))

    code, stdout, _ = run_command(["tasklist"])
    if code == 0:
        for line in stdout.splitlines():
            lowered = line.lower()
            if "avp.exe" in lowered or "klnagent" in lowered:
                findings.append(make_finding("kaspersky", "Kaspersky process running", "info", line.strip(), "defensive_process_running"))
    return {"findings": findings, "meta": {"product_count": len(products)}}


def check_network_surface():
    findings = []
    code, stdout, stderr = run_command(["netstat", "-ano"])
    if code != 0:
        return {"findings": [make_finding("network", "Listener enumeration failed", "medium", (stderr or stdout).strip(), "coverage_gap")], "meta": {}}

    risky_ports = {"80": "http", "135": "rpc", "139": "netbios", "445": "smb", "3389": "rdp", "5985": "winrm", "5986": "winrm_tls", "47001": "winrm_plugin"}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP" or parts[3].upper() != "LISTENING":
            continue
        local = parts[1]
        if ":" not in local:
            continue
        port = local.rsplit(":", 1)[-1]
        if port in risky_ports:
            findings.append(make_finding("network", "Sensitive listening port exposed", "info", f"{local} | pid={parts[4]} | service={risky_ports[port]}", "exposed_service_surface", local))
    return {"findings": findings, "meta": {}}


def run_all_checks(target):
    identity = get_identity_context()
    domain = os.environ.get("USERDNSDOMAIN") or os.environ.get("USERDOMAIN") or ""
    modules = [
        ("hotfixes", check_hotfixes),
        ("registry", check_registry_misconfig),
        ("unattend_gpp", lambda: check_unattend_and_gpp(domain)),
        ("services", lambda: check_services(identity)),
        ("tasks", lambda: check_tasks(identity)),
        ("autoruns", lambda: check_autoruns(identity)),
        ("path", lambda: check_path_hijack(identity)),
        ("files", lambda: check_file_loot(target)),
        ("token", check_local_identity),
        ("kaspersky", check_kaspersky),
        ("network", check_network_surface),
    ]

    results = {"identity": identity, "checks": {}, "findings": [], "meta": {}}
    for name, runner in modules:
        result = runner()
        results["checks"][name] = result
        results["findings"].extend(result.get("findings", []))
        if result.get("meta"):
            results["meta"][name] = result["meta"]

    score = 0
    for finding in results["findings"]:
        score += {"critical": 25, "high": 12, "medium": 5, "info": 1}.get(finding["level"], 0)
    results["score"] = min(score, 100)
    results["severity"] = severity(results["score"])
    return results
