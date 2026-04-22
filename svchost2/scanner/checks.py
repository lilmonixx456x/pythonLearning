import os
import re
from pathlib import Path

from .acl import extract_candidate_hijack_paths, find_writable_parent, get_identity_context, has_unquoted_space_path
from .system import existing_paths, expand_env_path, first_existing_parent, normalized_path, powershell_json, read_text_file, run_command, split_command_path


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
TASK_LOLBINS = ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe")


def severity(score):
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def make_finding(check_id, title, level, evidence, risk, path="", confidence="probable", refs=None):
    return {
        "check": check_id,
        "title": title,
        "level": level,
        "evidence": evidence,
        "risk": risk,
        "path": path,
        "confidence": confidence,
        "refs": refs or {},
    }


def check_hotfixes():
    data = powershell_json(
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object HotFixID, InstalledOn, Description | ConvertTo-Json -Depth 2"
    )
    findings = []
    latest = None
    if isinstance(data, dict) and data.get("error"):
        findings.append(make_finding("hotfix", "Hotfix inventory unavailable", "medium", data["error"], "patch_level_unknown", confidence="weak"))
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
                confidence="confirmed",
            )
        )
    return {"findings": findings, "meta": {"latest_hotfix": latest}}


def check_registry_misconfig():
    findings = []
    script = (
        "$paths=@("
        "[pscustomobject]@{Root='HKLM';Path='HKLM:\\Software\\Policies\\Microsoft\\Windows\\Installer';Name='AlwaysInstallElevated'},"
        "[pscustomobject]@{Root='HKCU';Path='HKCU:\\Software\\Policies\\Microsoft\\Windows\\Installer';Name='AlwaysInstallElevated'},"
        "[pscustomobject]@{Root='Winlogon';Path='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';Name='AutoAdminLogon'},"
        "[pscustomobject]@{Root='Winlogon';Path='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';Name='DefaultPassword'},"
        "[pscustomobject]@{Root='Winlogon';Path='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';Name='DefaultUserName'},"
        "[pscustomobject]@{Root='SystemPolicy';Path='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';Name='EnableLUA'},"
        "[pscustomobject]@{Root='SystemPolicy';Path='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';Name='LocalAccountTokenFilterPolicy'}"
        ");"
        "$out=foreach($item in $paths){"
        "  if(Test-Path $item.Path){"
        "    $v=(Get-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction SilentlyContinue).($item.Name);"
        "    [pscustomobject]@{Root=$item.Root;Path=$item.Path;Name=$item.Name;Value=$v}"
        "  }"
        "};"
        "$out | ConvertTo-Json -Depth 3"
    )
    data = powershell_json(script)
    if isinstance(data, dict) and data.get("error"):
        return {"findings": [make_finding("registry", "Registry inspection failed", "medium", data["error"], "coverage_gap", confidence="weak")], "meta": {}}

    values = {f"{item['Root']}::{item['Name']}": item.get("Value") for item in data}
    if values.get("HKLM::AlwaysInstallElevated") == 1 and values.get("HKCU::AlwaysInstallElevated") == 1:
        findings.append(make_finding("registry", "AlwaysInstallElevated fully enabled", "critical", "HKLM and HKCU values are both 1", "msi_privilege_escalation_path", confidence="confirmed", refs=values))
    if str(values.get("Winlogon::AutoAdminLogon")).strip() == "1":
        findings.append(make_finding("registry", "AutoAdminLogon enabled", "high", f"DefaultUserName={values.get('Winlogon::DefaultUserName')}", "autologon_enabled", confidence="confirmed", refs=values))
    if values.get("Winlogon::DefaultPassword") not in (None, ""):
        findings.append(make_finding("registry", "DefaultPassword present in Winlogon", "critical", "DefaultPassword registry value is populated", "cleartext_autologon_password", confidence="confirmed", refs=values))
    if values.get("SystemPolicy::EnableLUA") == 0:
        findings.append(make_finding("registry", "UAC disabled", "high", "EnableLUA is 0", "uac_disabled", confidence="confirmed", refs=values))
    if values.get("SystemPolicy::LocalAccountTokenFilterPolicy") == 1:
        findings.append(make_finding("registry", "Remote UAC filtering relaxed", "medium", "LocalAccountTokenFilterPolicy is 1", "remote_uac_relaxed", confidence="confirmed", refs=values))
    return {"findings": findings, "meta": values}


def check_boot_registry_surfaces():
    findings = []
    script = (
        "$items=@();"
        "$win='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';"
        "$sm='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager';"
        "$wd='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest';"
        "$lsa='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa';"
        "$ifeo='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options';"
        "$app='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows';"
        "$known='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs';"
        "$items += [pscustomobject]@{Key='Winlogon';Name='Shell';Value=(Get-ItemProperty -Path $win -Name Shell -ErrorAction SilentlyContinue).Shell};"
        "$items += [pscustomobject]@{Key='Winlogon';Name='Userinit';Value=(Get-ItemProperty -Path $win -Name Userinit -ErrorAction SilentlyContinue).Userinit};"
        "$items += [pscustomobject]@{Key='Windows';Name='AppInit_DLLs';Value=(Get-ItemProperty -Path $app -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs};"
        "$items += [pscustomobject]@{Key='Windows';Name='LoadAppInit_DLLs';Value=(Get-ItemProperty -Path $app -Name LoadAppInit_DLLs -ErrorAction SilentlyContinue).LoadAppInit_DLLs};"
        "$items += [pscustomobject]@{Key='SessionManager';Name='BootExecute';Value=(Get-ItemProperty -Path $sm -Name BootExecute -ErrorAction SilentlyContinue).BootExecute};"
        "$items += [pscustomobject]@{Key='SessionManager';Name='PendingFileRenameOperations';Value=(Get-ItemProperty -Path $sm -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations};"
        "$items += [pscustomobject]@{Key='WDigest';Name='UseLogonCredential';Value=(Get-ItemProperty -Path $wd -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential};"
        "$items += [pscustomobject]@{Key='LSA';Name='RunAsPPL';Value=(Get-ItemProperty -Path $lsa -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL};"
        "$items += [pscustomobject]@{Key='LSA';Name='LsaCfgFlags';Value=(Get-ItemProperty -Path $lsa -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags};"
        "$items += [pscustomobject]@{Key='LSA';Name='DisableRestrictedAdmin';Value=(Get-ItemProperty -Path $lsa -Name DisableRestrictedAdmin -ErrorAction SilentlyContinue).DisableRestrictedAdmin};"
        "if(Test-Path $ifeo){Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {"
        "  $dbg=(Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger;"
        "  if($dbg){$items += [pscustomobject]@{Key='IFEO';Name=$_.PSChildName;Value=$dbg}}"
        "}};"
        "if(Test-Path $known){Get-ItemProperty -Path $known -ErrorAction SilentlyContinue | ForEach-Object {$_.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {$items += [pscustomobject]@{Key='KnownDLLs';Name=$_.Name;Value=$_.Value}}}};"
        "$items | ConvertTo-Json -Depth 4"
    )
    data = powershell_json(script)
    if isinstance(data, dict) and data.get("error"):
        return {"findings": [make_finding("boot_registry", "Boot/LSA registry inspection failed", "medium", data["error"], "coverage_gap", confidence="weak")], "meta": {}}

    meta = {}
    for item in data:
        key = f"{item.get('Key')}::{item.get('Name')}"
        value = item.get("Value")
        meta[key] = value
        text = str(value or "").strip()
        lower = text.lower()
        if key == "Windows::LoadAppInit_DLLs" and str(value).strip() == "1":
            findings.append(make_finding("boot_registry", "AppInit DLL loading enabled", "high", "LoadAppInit_DLLs is 1", "appinit_dll_injection_surface", confidence="confirmed"))
        if key == "Windows::AppInit_DLLs" and text:
            findings.append(make_finding("boot_registry", "AppInit_DLLs populated", "critical", text, "appinit_dll_injection_surface", confidence="confirmed"))
        if key == "Winlogon::Shell" and text and lower != "explorer.exe":
            findings.append(make_finding("boot_registry", "Non-default Winlogon shell", "high", text, "custom_logon_shell", confidence="confirmed"))
        if key == "Winlogon::Userinit" and text and "userinit.exe" not in lower:
            findings.append(make_finding("boot_registry", "Non-default Userinit", "high", text, "custom_userinit_chain", confidence="confirmed"))
        if key == "SessionManager::BootExecute" and text and "autocheck autochk *" not in lower:
            findings.append(make_finding("boot_registry", "Non-default BootExecute", "high", text, "boot_execute_hook", confidence="confirmed"))
        if key == "SessionManager::PendingFileRenameOperations" and text:
            findings.append(make_finding("boot_registry", "PendingFileRenameOperations present", "info", text[:500], "pending_boot_time_file_replace", confidence="confirmed"))
        if key == "WDigest::UseLogonCredential" and str(value).strip() == "1":
            findings.append(make_finding("boot_registry", "WDigest stores logon credentials", "critical", "UseLogonCredential is 1", "credential_material_in_memory", confidence="confirmed"))
        if key == "LSA::RunAsPPL" and str(value).strip() == "0":
            findings.append(make_finding("boot_registry", "LSASS PPL disabled", "medium", "RunAsPPL is 0", "lsa_protection_weakened", confidence="confirmed"))
        if key == "IFEO::" or item.get("Key") == "IFEO":
            findings.append(make_finding("boot_registry", "IFEO debugger entry present", "critical", f"{item.get('Name')} => {text}", "ifeo_execution_hijack", confidence="confirmed"))
    return {"findings": findings, "meta": meta}


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
                            findings.append(make_finding("gpp", "Sensitive XML in SYSVOL", "critical", f"{full_path} | markers={', '.join(markers)}", "credential_material_exposed", full_path, confidence="confirmed"))
                if len(findings) >= 20:
                    return {"findings": findings, "meta": {"searched": paths}}
        else:
            content = read_text_file(path, 20000).lower()
            markers = [marker for marker in ("autologon", "defaultpassword", "<password>", "<plaintext>true</plaintext>") if marker in content]
            if markers:
                findings.append(make_finding("unattend", "Sensitive unattend material", "critical", f"{path} | markers={', '.join(markers)}", "credential_material_exposed", path, confidence="confirmed"))

    return {"findings": findings, "meta": {"searched": paths}}


def check_services(identity):
    findings = []
    data = powershell_json(
        "Get-CimInstance Win32_Service | ForEach-Object {"
        "  [pscustomobject]@{"
        "    Name=$_.Name;"
        "    DisplayName=$_.DisplayName;"
        "    StartName=$_.StartName;"
        "    State=$_.State;"
        "    PathName=$_.PathName"
        "  }"
        "} | ConvertTo-Json -Depth 4"
    )
    if isinstance(data, dict) and data.get("error"):
        return {"findings": [make_finding("service", "Service enumeration failed", "medium", data["error"], "coverage_gap", confidence="weak")], "meta": {}}

    privileged_refs = []
    for item in data:
        command_line = (item.get("PathName") or "").strip()
        image_path, _ = split_command_path(command_line)
        start_name = item.get("StartName") or ""
        privileged = any(token in start_name.lower() for token in ("localsystem", "localservice", "networkservice", "nt authority"))
        if privileged:
            privileged_refs.append({"name": item.get("Name"), "path": image_path, "command": command_line})

        if has_unquoted_space_path(command_line) and privileged:
            findings.append(
                make_finding(
                    "service",
                    "Unquoted privileged service path",
                    "high",
                    f"{item.get('Name')} | {command_line}",
                    "service_path_hijack",
                    image_path or command_line,
                    confidence="probable",
                    refs={"service": item.get("Name"), "account": start_name},
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
                            confidence="confirmed",
                            refs={"service": item.get("Name"), "account": start_name, "acl": parent_check},
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
                            confidence="confirmed",
                            refs={"service": item.get("Name"), "account": start_name, "acl": acl},
                        )
                    )
    return {"findings": findings, "meta": {"count": len(data), "privileged_services": privileged_refs[:100]}}


def check_service_dlls(identity):
    findings = []
    script = (
        "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services' -ErrorAction SilentlyContinue | ForEach-Object {"
        "  $name=$_.PSChildName;"
        "  $svc=Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue;"
        "  $params=Get-ItemProperty -Path ($_.PSPath + '\\Parameters') -ErrorAction SilentlyContinue;"
        "  if($params.ServiceDll -or $svc.ImagePath){"
        "    [pscustomobject]@{Name=$name;ImagePath=$svc.ImagePath;ObjectName=$svc.ObjectName;ServiceDll=$params.ServiceDll}"
        "  }"
        "} | ConvertTo-Json -Depth 4"
    )
    data = powershell_json(script, timeout=90)
    if isinstance(data, dict) and data.get("error"):
        return {"findings": [make_finding("service_dll", "ServiceDll inspection failed", "medium", data["error"], "coverage_gap", confidence="weak")], "meta": {}}

    refs = []
    for item in data:
        service_name = item.get("Name")
        object_name = str(item.get("ObjectName") or "")
        privileged = any(token in object_name.lower() for token in ("localsystem", "localservice", "networkservice", "nt authority"))
        service_dll = expand_env_path(item.get("ServiceDll") or "")
        image_path, _ = split_command_path(expand_env_path(item.get("ImagePath") or ""))
        if privileged:
            refs.append({"name": service_name, "path": service_dll or image_path})
        for candidate_path, risk in ((service_dll, "service_dll_hijack"), (image_path, "service_imagepath_hijack")):
            if not candidate_path or not privileged:
                continue
            parent = first_existing_parent(candidate_path)
            if parent:
                acl = find_writable_parent(parent, identity)
                if acl["writable"]:
                    findings.append(make_finding("service_dll", "Privileged service component in writable location", "critical", f"{service_name} | {candidate_path} | acl={acl['reason']}", risk, candidate_path, confidence="confirmed", refs={"service": service_name, "acl": acl}))
    return {"findings": findings, "meta": {"count": len(data), "privileged_service_components": refs[:100]}}


def check_tasks(identity):
    findings = []
    data = powershell_json(
        "Get-ScheduledTask | ForEach-Object {"
        "  $task=$_;"
        "  foreach($action in $task.Actions){"
        "    [pscustomobject]@{"
        "      TaskName=$task.TaskPath + $task.TaskName;"
        "      RunAs=$task.Principal.UserId;"
        "      RunLevel=$task.Principal.RunLevel;"
        "      ActionType=$action.CimClass.CimClassName;"
        "      Execute=$action.Execute;"
        "      Arguments=$action.Arguments;"
        "      WorkingDirectory=$action.WorkingDirectory;"
        "      ClassId=$action.ClassId"
        "    }"
        "  }"
        "} | ConvertTo-Json -Depth 5"
    )
    if isinstance(data, dict) and data.get("error"):
        return {"findings": [make_finding("task", "Scheduled task enumeration failed", "medium", data["error"], "coverage_gap", confidence="weak")], "meta": {}}

    privileged_refs = []
    for row in data:
        run_as = (row.get("RunAs") or "").lower()
        task_name = row.get("TaskName") or ""
        execute = expand_env_path(row.get("Execute") or "")
        arguments = row.get("Arguments") or ""
        command = " ".join(part for part in [execute, arguments] if part).strip()
        privileged = any(token in run_as for token in ("system", "administrator", "service")) or str(row.get("RunLevel", "")).lower() == "highest"
        if privileged:
            privileged_refs.append({"task": task_name, "execute": execute, "arguments": arguments})
        action_type = str(row.get("ActionType") or "")
        if not execute:
            if action_type.lower().endswith("comhandleraction") and privileged:
                findings.append(make_finding("task", "Privileged task uses COM handler", "high", f"{task_name} | ClassId={row.get('ClassId')}", "task_com_handler_surface", confidence="confirmed", refs=row))
            continue

        if privileged and has_unquoted_space_path(command):
            findings.append(make_finding("task", "Unquoted privileged task action", "high", f"{task_name} | {command}", "task_path_hijack", execute, confidence="probable", refs=row))
        if privileged and any(lolbin in execute.lower() for lolbin in TASK_LOLBINS):
            findings.append(make_finding("task", "Privileged task uses LOLBin", "medium", f"{task_name} | {command}", "task_lolbin_execution_surface", execute, confidence="confirmed", refs=row))

        parent = first_existing_parent(execute)
        if privileged and parent:
            acl = find_writable_parent(parent, identity)
            if acl["writable"]:
                findings.append(
                    make_finding(
                        "task",
                        "Privileged task points to writable location",
                        "critical",
                        f"{task_name} | {execute} | acl={acl['reason']}",
                        "task_binary_replacement_or_script_swap",
                        execute,
                        confidence="confirmed",
                        refs={"task": row, "acl": acl},
                    )
                )

        working_dir = expand_env_path(row.get("WorkingDirectory") or "")
        if privileged and working_dir and Path(working_dir).exists():
            acl = find_writable_parent(working_dir, identity)
            if acl["writable"]:
                findings.append(
                    make_finding(
                        "task",
                        "Privileged task working directory writable",
                        "high",
                        f"{task_name} | {working_dir} | acl={acl['reason']}",
                        "task_working_dir_hijack",
                        working_dir,
                        confidence="confirmed",
                        refs={"task": row, "acl": acl},
                    )
                )
    return {"findings": findings, "meta": {"count": len(data), "privileged_tasks": privileged_refs[:100]}}


def check_wmi_persistence():
    findings = []
    script = (
        "$ns='root\\subscription';"
        "$filters=Get-WmiObject -Namespace $ns -Class __EventFilter -ErrorAction SilentlyContinue | "
        "Select-Object Name,Query,EventNamespace;"
        "$cmd=Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | "
        "Select-Object Name,ExecutablePath,CommandLineTemplate;"
        "$scriptc=Get-WmiObject -Namespace $ns -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue | "
        "Select-Object Name,ScriptingEngine,ScriptText;"
        "$bind=Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | "
        "Select-Object Filter,Consumer;"
        "[pscustomobject]@{Filters=$filters;CommandConsumers=$cmd;ScriptConsumers=$scriptc;Bindings=$bind} | ConvertTo-Json -Depth 6"
    )
    data = powershell_json(script, timeout=90)
    if isinstance(data, dict) and data.get("error"):
        return {"findings": [make_finding("wmi", "WMI persistence inspection failed", "medium", data["error"], "coverage_gap", confidence="weak")], "meta": {}}
    record = data[0] if isinstance(data, list) and data else data
    filters = record.get("Filters") or []
    cmd = record.get("CommandConsumers") or []
    scriptc = record.get("ScriptConsumers") or []
    bindings = record.get("Bindings") or []
    if isinstance(filters, dict):
        filters = [filters]
    if isinstance(cmd, dict):
        cmd = [cmd]
    if isinstance(scriptc, dict):
        scriptc = [scriptc]
    if isinstance(bindings, dict):
        bindings = [bindings]
    for item in cmd:
        findings.append(make_finding("wmi", "WMI CommandLineEventConsumer present", "critical", f"{item.get('Name')} | {item.get('ExecutablePath') or item.get('CommandLineTemplate')}", "wmi_command_consumer_persistence", confidence="confirmed", refs=item))
    for item in scriptc:
        findings.append(make_finding("wmi", "WMI ActiveScriptEventConsumer present", "critical", f"{item.get('Name')} | {item.get('ScriptingEngine')}", "wmi_script_consumer_persistence", confidence="confirmed", refs=item))
    if bindings:
        findings.append(make_finding("wmi", "WMI subscription bindings present", "high", f"bindings={len(bindings)} filters={len(filters)}", "wmi_persistence_chain_present", confidence="confirmed"))
    return {"findings": findings, "meta": {"filters": len(filters), "command_consumers": len(cmd), "script_consumers": len(scriptc), "bindings": len(bindings)}}


def check_bits_jobs():
    findings = []
    script = (
        "Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | "
        "Select-Object DisplayName,Description,JobState,OwnerAccount,NotifyCmdLine,Files | ConvertTo-Json -Depth 6"
    )
    data = powershell_json(script, timeout=90)
    if isinstance(data, dict) and data.get("error"):
        code, stdout, stderr = run_command(["bitsadmin", "/list", "/allusers", "/verbose"], timeout=90)
        if code != 0:
            return {"findings": [make_finding("bits", "BITS inspection failed", "medium", data["error"] or (stderr or stdout).strip(), "coverage_gap", confidence="weak")], "meta": {}}
        text = stdout.lower()
        if "notify cmd line" in text or "owner:" in text:
            findings.append(make_finding("bits", "BITS jobs detected via bitsadmin", "medium", stdout[:1200], "bits_transfer_artifacts", confidence="confirmed"))
        return {"findings": findings, "meta": {"fallback": "bitsadmin"}}
    if isinstance(data, list):
        for item in data:
            notify = item.get("NotifyCmdLine")
            if notify:
                findings.append(make_finding("bits", "BITS job with notify command", "high", f"{item.get('DisplayName')} | {notify}", "bits_notify_command_execution", confidence="confirmed", refs=item))
            else:
                findings.append(make_finding("bits", "BITS job present", "info", f"{item.get('DisplayName')} | state={item.get('JobState')} | owner={item.get('OwnerAccount')}", "bits_transfer_artifacts", confidence="confirmed", refs=item))
    return {"findings": findings, "meta": {"count": len(data) if isinstance(data, list) else 0}}


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
            findings.append(make_finding("autorun", "Writable Startup folder", "high", f"{startup_dir} | acl={acl['reason']}", "autorun_drop_path", startup_dir, confidence="confirmed"))

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
                                confidence="confirmed",
                                refs={"registry_key": key, "value": value_data, "acl": acl},
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
            findings.append(make_finding("path", "Writable PATH directory", "high", f"{expanded} | acl={acl['reason']}", "path_hijack", expanded, confidence="confirmed", refs={"acl": acl}))
    return {"findings": findings, "meta": {"count": len(seen)}}


def _file_priority_roots(target, references):
    roots = [target, r"C:\ProgramData"]
    for item in references:
        for key in ("path", "execute"):
            value = item.get(key)
            if value:
                parent = first_existing_parent(value)
                if parent:
                    roots.append(parent)
    seen = set()
    ordered = []
    for root in roots:
        root = normalized_path(root)
        if not root or root.lower() in seen:
            continue
        seen.add(root.lower())
        ordered.append(root)
    return ordered


def check_file_loot(target, references):
    findings = []
    roots = _file_priority_roots(target, references)
    scanned_total = 0
    for root in roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        for base, _, files in os.walk(root):
            for name in files:
                scanned_total += 1
                if scanned_total > 6000:
                    return {"findings": findings, "meta": {"truncated": True, "roots": roots, "scanned_total": scanned_total}}
                full_path = str(Path(base) / name)
                lowered = name.lower()
                if not any(part in lowered for part in SUSPICIOUS_FILE_NAMES) and Path(name).suffix.lower() not in SUSPICIOUS_EXTENSIONS:
                    continue
                content = read_text_file(full_path, 12000).lower()
                markers = [token for token in SUSPICIOUS_CONTENT if token in content]
                if markers:
                    level = "high" if any(token in markers for token in ("cpassword", "defaultpassword", "autoadminlogon")) else "medium"
                    findings.append(make_finding("files", "Interesting file with credential markers", level, f"{full_path} | markers={', '.join(markers)}", "possible_credentials_or_config", full_path, confidence="confirmed"))
    return {"findings": findings, "meta": {"roots": roots, "scanned_total": scanned_total}}


def check_local_identity():
    findings = []
    code, stdout, stderr = run_command(["whoami", "/priv"])
    output = (stdout or stderr).strip()
    if code == 0 and output:
        for privilege in ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"):
            if privilege in output:
                findings.append(make_finding("token", "Interesting user privilege present", "high", privilege, "local_privilege_path", confidence="confirmed"))
    return {"findings": findings, "meta": {}}


def check_smb_surface(identity):
    findings = []
    script = (
        "$cfg=Get-SmbServerConfiguration -ErrorAction SilentlyContinue | "
        "Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature,RejectUnencryptedAccess;"
        "$shares=Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,Description,ScopeName;"
        "$shareAccess=foreach($s in $shares){Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | Select-Object @{n='ShareName';e={$s.Name}},AccountName,AccessControlType,AccessRight};"
        "[pscustomobject]@{Config=$cfg;Shares=$shares;ShareAccess=$shareAccess} | ConvertTo-Json -Depth 6"
    )
    data = powershell_json(script, timeout=90)
    if isinstance(data, dict) and data.get("error"):
        return {"findings": [make_finding("smb", "SMB inspection failed", "medium", data["error"], "coverage_gap", confidence="weak")], "meta": {}}
    record = data[0] if isinstance(data, list) and data else data
    config = record.get("Config") or {}
    shares = record.get("Shares") or []
    access = record.get("ShareAccess") or []
    if isinstance(config, list):
        config = config[0] if config else {}
    if isinstance(shares, dict):
        shares = [shares]
    if isinstance(access, dict):
        access = [access]
    if config.get("EnableSMB1Protocol") is True:
        findings.append(make_finding("smb", "SMBv1 enabled", "critical", "EnableSMB1Protocol=True", "smbv1_legacy_surface", confidence="confirmed", refs=config))
    if config.get("RequireSecuritySignature") is False and config.get("EnableSecuritySignature") is False:
        findings.append(make_finding("smb", "SMB signing not enforced", "medium", "RequireSecuritySignature=False and EnableSecuritySignature=False", "smb_signing_weakened", confidence="confirmed", refs=config))
    share_map = {}
    for item in access:
        share_map.setdefault(item.get("ShareName"), []).append(item)
    for share in shares:
        path = share.get("Path") or ""
        share_name = share.get("Name")
        share_access = share_map.get(share_name, [])
        broad = [a for a in share_access if str(a.get("AccessControlType")).lower() == "allow" and str(a.get("AccountName", "")).lower() in ("everyone", "builtin\\users", "authenticated users", "users")]
        if broad:
            findings.append(make_finding("smb", "Share has broad share-level access", "high", f"{share_name} | broad={', '.join(a.get('AccountName') for a in broad)}", "broad_share_permissions", path, confidence="confirmed", refs={"share": share, "share_access": broad}))
        if path and Path(path).exists():
            acl = find_writable_parent(path, identity)
            if broad and acl["writable"]:
                findings.append(make_finding("smb", "Share and NTFS both writable to broad principals", "critical", f"{share_name} | path={path} | share_access={', '.join(a.get('AccountName') for a in broad)} | acl={acl['reason']}", "share_ntfs_write_overlap", path, confidence="confirmed", refs={"share": share, "share_access": broad, "acl": acl}))
    return {"findings": findings, "meta": {"shares": len(shares), "share_access_entries": len(access), "config": config}}


def check_saved_credentials():
    findings = []
    code, stdout, stderr = run_command(["cmdkey", "/list"], timeout=60)
    if code == 0:
        targets = [line.strip() for line in stdout.splitlines() if "Target:" in line or "Цель:" in line]
        if targets:
            findings.append(make_finding("creds", "Saved credentials in Credential Manager", "high", " | ".join(targets[:20]), "stored_credentials_present", confidence="confirmed"))
    code, stdout, _ = run_command(["net", "use"], timeout=60)
    if code == 0:
        lines = [line.strip() for line in stdout.splitlines() if "\\" in line]
        if lines:
            findings.append(make_finding("creds", "Mapped network resources present", "info", " | ".join(lines[:20]), "network_resource_artifacts", confidence="confirmed"))
    profile = Path(expand_env_path(r"%USERPROFILE%"))
    search_roots = [profile, profile / "Documents", profile / "Desktop", profile / "Downloads", profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"]
    checked = 0
    for root in search_roots:
        if not root.exists():
            continue
        for base, _, files in os.walk(root):
            for name in files:
                checked += 1
                if checked > 3000:
                    return {"findings": findings, "meta": {"checked": checked, "truncated": True}}
                full = Path(base) / name
                lower = name.lower()
                if lower.endswith(".rdp"):
                    content = read_text_file(full, 8000).lower()
                    markers = [m for m in ("username:s:", "full address:s:", "gatewayhostname:s:") if m in content]
                    findings.append(make_finding("creds", "RDP file present", "medium", f"{full} | markers={','.join(markers) or 'none'}", "rdp_connection_artifact", str(full), confidence="confirmed"))
                elif lower in ("winscp.ini", "putty.reg") or "rdg" in lower:
                    findings.append(make_finding("creds", "Remote access profile artifact present", "medium", str(full), "remote_access_profile_artifact", str(full), confidence="confirmed"))
    return {"findings": findings, "meta": {"checked": checked}}


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
        findings.append(make_finding("kaspersky", "Kaspersky product detected", "info", f"{item.get('DisplayName')} {item.get('DisplayVersion') or ''}", "defensive_stack_present", confidence="confirmed"))

    code, stdout, _ = run_command(["tasklist"])
    if code == 0:
        for line in stdout.splitlines():
            lowered = line.lower()
            if "avp.exe" in lowered or "klnagent" in lowered:
                findings.append(make_finding("kaspersky", "Kaspersky process running", "info", line.strip(), "defensive_process_running", confidence="confirmed"))
    return {"findings": findings, "meta": {"product_count": len(products)}}


def check_network_surface():
    findings = []
    code, stdout, stderr = run_command(["netstat", "-ano"])
    if code != 0:
        return {"findings": [make_finding("network", "Listener enumeration failed", "medium", (stderr or stdout).strip(), "coverage_gap", confidence="weak")], "meta": {}}

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
            findings.append(make_finding("network", "Sensitive listening port exposed", "info", f"{local} | pid={parts[4]} | service={risky_ports[port]}", "exposed_service_surface", local, confidence="confirmed"))
    return {"findings": findings, "meta": {}}


def correlate_findings(results):
    findings = []
    privileged_services = results["meta"].get("services", {}).get("privileged_services", [])
    privileged_tasks = results["meta"].get("tasks", {}).get("privileged_tasks", [])
    writable_paths = [item["path"].lower() for item in results["findings"] if item["risk"] in {"path_hijack", "autorun_drop_path", "autorun_binary_swap"} and item.get("path")]

    for svc in privileged_services:
        path = (svc.get("path") or "").lower()
        if path and any(path.startswith(base) for base in writable_paths):
            findings.append(make_finding("correlation", "Writable PATH/autorun location overlaps privileged service", "critical", f"{svc['name']} | {svc['path']}", "correlated_privileged_write_path", svc["path"], confidence="confirmed", refs=svc))

    for task in privileged_tasks:
        execute = (task.get("execute") or "").lower()
        if execute and any(execute.startswith(base) for base in writable_paths):
            findings.append(make_finding("correlation", "Writable PATH/autorun location overlaps privileged task", "critical", f"{task['task']} | {task['execute']}", "correlated_privileged_write_path", task["execute"], confidence="confirmed", refs=task))
    share_paths = [item["path"].lower() for item in results["findings"] if item["risk"] == "share_ntfs_write_overlap" and item.get("path")]
    for svc in privileged_services:
        path = (svc.get("path") or "").lower()
        if path and any(path.startswith(base) for base in share_paths):
            findings.append(make_finding("correlation", "Writable share path overlaps privileged service", "critical", f"{svc['name']} | {svc['path']}", "share_backed_privileged_binary_path", svc["path"], confidence="confirmed", refs=svc))
    return findings


def run_all_checks(target):
    identity = get_identity_context()
    domain = os.environ.get("USERDNSDOMAIN") or os.environ.get("USERDOMAIN") or ""
    modules = [
        ("hotfixes", check_hotfixes),
        ("registry", check_registry_misconfig),
        ("boot_registry", check_boot_registry_surfaces),
        ("unattend_gpp", lambda: check_unattend_and_gpp(domain)),
        ("services", lambda: check_services(identity)),
        ("service_dll", lambda: check_service_dlls(identity)),
        ("tasks", lambda: check_tasks(identity)),
        ("wmi", check_wmi_persistence),
        ("bits", check_bits_jobs),
        ("autoruns", lambda: check_autoruns(identity)),
        ("path", lambda: check_path_hijack(identity)),
        ("files", None),
        ("token", check_local_identity),
        ("smb", lambda: check_smb_surface(identity)),
        ("creds", check_saved_credentials),
        ("kaspersky", check_kaspersky),
        ("network", check_network_surface),
    ]

    results = {"identity": identity, "checks": {}, "findings": [], "meta": {}}
    for name, runner in modules:
        if runner is None:
            continue
        result = runner()
        results["checks"][name] = result
        results["findings"].extend(result.get("findings", []))
        if result.get("meta"):
            results["meta"][name] = result["meta"]

    references = []
    references.extend(results["meta"].get("services", {}).get("privileged_services", []))
    references.extend(results["meta"].get("service_dll", {}).get("privileged_service_components", []))
    references.extend(results["meta"].get("tasks", {}).get("privileged_tasks", []))
    file_result = check_file_loot(target, references)
    results["checks"]["files"] = file_result
    results["findings"].extend(file_result.get("findings", []))
    results["meta"]["files"] = file_result.get("meta", {})

    correlated = correlate_findings(results)
    results["checks"]["correlation"] = {"findings": correlated, "meta": {"count": len(correlated)}}
    results["findings"].extend(correlated)
    results["meta"]["correlation"] = {"count": len(correlated)}

    deduped = []
    seen = set()
    for finding in results["findings"]:
        key = (finding["check"], finding["title"], finding.get("path", ""), finding["risk"], finding["evidence"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    results["findings"] = deduped

    score = 0
    for finding in results["findings"]:
        base = {"critical": 25, "high": 12, "medium": 5, "info": 1}.get(finding["level"], 0)
        confidence_boost = {"confirmed": 1.2, "probable": 1.0, "weak": 0.6}.get(finding.get("confidence", "probable"), 1.0)
        score += int(base * confidence_boost)
    results["score"] = min(score, 100)
    results["severity"] = severity(results["score"])
    return results
