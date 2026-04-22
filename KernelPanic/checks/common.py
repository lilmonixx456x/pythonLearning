import ctypes
import os
import subprocess
from datetime import datetime
from pathlib import Path


def is_windows():
    return os.name == "nt"


def run_command(cmd):
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=30,
            encoding="utf-8",
            errors="replace",
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def current_identity():
    if not is_windows():
        return {"user": os.environ.get("USER", "unknown"), "is_admin": False}
    try:
        return {
            "user": os.environ.get("USERNAME", "unknown"),
            "is_admin": bool(ctypes.windll.shell32.IsUserAnAdmin()),
        }
    except Exception:
        return {"user": os.environ.get("USERNAME", "unknown"), "is_admin": False}


def check_write_access(path):
    test_file = Path(path) / f".permcheck_{os.getpid()}.tmp"
    try:
        with open(test_file, "w", encoding="utf-8") as handle:
            handle.write("check")
        test_file.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def write_report(report_path, data):
    lines = []
    lines.append("Windows risk-check report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"Host user: {data['identity']['user']}")
    lines.append(f"Admin token: {data['identity']['is_admin']}")
    lines.append("")

    hotfix_date = data.get("latest_hotfix")
    lines.append(f"Latest hotfix date found: {hotfix_date if hotfix_date else 'unavailable'}")
    lines.append("")

    lines.append("[1] Writable startup paths")
    startup = data.get("startup", [])
    if startup:
        for item in startup:
            entries = ", ".join(item["entries"]) if item["entries"] else "none"
            lines.append(f"- {item['path']} | writable={item['writable']} | entries={entries}")
    else:
        lines.append("- none found")
    lines.append("")

    lines.append("[2] Interesting file findings")
    file_findings = data.get("file_scan", {}).get("findings", [])
    if file_findings:
        for item in file_findings[:100]:
            reasons = ",".join(item["reasons"])
            lines.append(f"- {item['path']} | writable_parent={item['writable']} | reasons={reasons}")
        if len(file_findings) > 100:
            lines.append(f"- truncated output: showing 100 of {len(file_findings)} findings")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[3] High-privilege services with writable directories")
    service_findings = data.get("service_findings", [])
    if isinstance(service_findings, dict) and service_findings.get("error"):
        lines.append(f"- error: {service_findings['error']}")
    elif service_findings:
        for item in service_findings:
            flags = ",".join(item["risk_flags"])
            lines.append(
                f"- {item['name']} | account={item['start_name']} | state={item['state']} | "
                f"flags={flags} | path={item['path_name']}"
            )
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[4] Interesting scheduled tasks")
    task_findings = data.get("task_findings", [])
    if isinstance(task_findings, dict) and task_findings.get("error"):
        lines.append(f"- error: {task_findings['error']}")
    elif task_findings:
        for item in task_findings[:100]:
            lines.append(f"- {item['task']} | state={item['state']} | author={item['author']}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[5] Exposed listeners")
    listener_findings = data.get("listener_findings", [])
    if isinstance(listener_findings, dict) and listener_findings.get("error"):
        lines.append(f"- error: {listener_findings['error']}")
    elif listener_findings:
        for item in listener_findings:
            lines.append(f"- {item.get('LocalAddress')}:{item.get('LocalPort')} | pid={item.get('OwningProcess')}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[6] SMB shares")
    shares = data.get("shares", [])
    if isinstance(shares, dict) and shares.get("error"):
        lines.append(f"- error: {shares['error']}")
    elif shares:
        for item in shares:
            lines.append(f"- {item.get('Name')} | path={item.get('Path')} | desc={item.get('Description') or ''}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[7] AlwaysInstallElevated")
    aie = data.get("always_install_elevated", {})
    if aie.get("error"):
        lines.append(f"- error: {aie['error']}")
    else:
        lines.append(
            f"- HKLM={aie.get('HKLM')} | HKCU={aie.get('HKCU')} | vulnerable={aie.get('vulnerable')}"
        )
    lines.append("")

    lines.append("[8] AutoLogon")
    autologon = data.get("autologon", {})
    if autologon.get("error"):
        lines.append(f"- error: {autologon['error']}")
    else:
        lines.append(
            f"- enabled={autologon.get('enabled')} | user={autologon.get('default_username')} | "
            f"domain={autologon.get('default_domain')} | password_present={autologon.get('password_present')}"
        )
    lines.append("")

    lines.append("[9] Unattend files")
    unattend = data.get("unattend", {})
    if unattend.get("error"):
        lines.append(f"- error: {unattend['error']}")
    elif unattend.get("findings"):
        for item in unattend["findings"]:
            lines.append(f"- {item['path']} | indicators={','.join(item['indicators'])}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[10] UAC policy")
    uac = data.get("uac_policy", {})
    if uac.get("error"):
        lines.append(f"- error: {uac['error']}")
    else:
        values = uac.get("values", {})
        lines.append(
            f"- EnableLUA={values.get('EnableLUA')} | ConsentPromptBehaviorAdmin={values.get('ConsentPromptBehaviorAdmin')} | "
            f"LocalAccountTokenFilterPolicy={values.get('LocalAccountTokenFilterPolicy')} | "
            f"findings={','.join(uac.get('findings', [])) or 'none'}"
        )
    lines.append("")

    lines.append("[11] Writable PATH directories")
    path_dirs = data.get("path_writable", [])
    if isinstance(path_dirs, dict) and path_dirs.get("error"):
        lines.append(f"- error: {path_dirs['error']}")
    elif path_dirs:
        for item in path_dirs:
            lines.append(f"- {item['path']} | writable={item['writable']}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[12] Unquoted service paths")
    unquoted = data.get("service_unquoted", [])
    if isinstance(unquoted, dict) and unquoted.get("error"):
        lines.append(f"- error: {unquoted['error']}")
    elif unquoted:
        for item in unquoted[:100]:
            lines.append(f"- {item['name']} | account={item['start_name']} | path={item['path_name']}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[13] Local Administrators group")
    admins = data.get("admin_group", [])
    if isinstance(admins, dict) and admins.get("error"):
        lines.append(f"- error: {admins['error']}")
    elif admins:
        for item in admins:
            lines.append(f"- {item.get('Name')} | type={item.get('ObjectClass')} | source={item.get('PrincipalSource')}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[14] Weak local user settings")
    local_users = data.get("local_users", [])
    if isinstance(local_users, dict) and local_users.get("error"):
        lines.append(f"- error: {local_users['error']}")
    elif local_users:
        for item in local_users:
            lines.append(f"- {item['name']} | flags={','.join(item['flags'])} | last_logon={item['last_logon']}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[15] Kaspersky presence and state")
    kaspersky = data.get("kaspersky", {})
    if kaspersky.get("error"):
        lines.append(f"- error: {kaspersky['error']}")
    else:
        products = kaspersky.get("Products", []) or []
        services = kaspersky.get("Services", []) or []
        processes = kaspersky.get("Processes", []) or []
        if isinstance(products, dict):
            products = [products]
        if isinstance(services, dict):
            services = [services]
        if isinstance(processes, dict):
            processes = [processes]
        lines.append(f"- products={len(products)} | services={len(services)} | processes={len(processes)}")
        for item in products[:20]:
            lines.append(f"- product: {item.get('DisplayName')} {item.get('DisplayVersion') or ''} | publisher={item.get('Publisher') or ''}")
        for item in services[:20]:
            lines.append(f"- service: {item.get('Name')} | status={item.get('Status')} | start={item.get('StartType')}")
    lines.append("")

    Path(report_path).write_text("\n".join(lines), encoding="utf-8")
